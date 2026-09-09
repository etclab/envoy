#include "source/extensions/transport_sockets/tls/cert_validator/rbe/rbe_validator.h"

#include <openssl/safestack.h>

#include <chrono>
#include <cstdint>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <sstream>
#include <utility>

#include "envoy/extensions/transport_sockets/tls/v3/common.pb.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls_rbe_validator_config.pb.h"
#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/stats/scope.h"

#include "source/common/config/datasource.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/tls/cert_validator/factory.h"
#include "source/common/tls/cert_validator/utility.h"
#include "source/common/tls/stats.h"
#include "source/common/tls/utility.h"

#include "openssl/ssl.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using RBEConfig = envoy::extensions::transport_sockets::tls::v3::RBECertValidatorConfig;

namespace {
// The X.509 extension carrying the peer's RBE admin token.
constexpr absl::string_view AdminTokenOid = "1.3.6.1.4.1.9901.33";
} // namespace

RBEValidator::RBEValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                 SslStats& stats,
                                 Server::Configuration::CommonFactoryContext& context)
    : tls_(ThreadLocal::TypedSlot<ThreadLocalCache>::makeUnique(context.threadLocal())),
      thread_factory_(Thread::PosixThreadFactory::create()),
      rbe_scope_(context.serverScope().createScope("rbe.")),
      rbe_stats_(std::make_unique<RBEStats>(*rbe_scope_)),
      stats_(stats), time_source_(context.timeSource()) {
  ASSERT(config != nullptr);

  if (config->customValidatorConfig().has_value()) {
    RBEConfig message;
    THROW_IF_NOT_OK(Config::Utility::translateOpaqueConfig(
        config->customValidatorConfig().value().typed_config(),
        ProtobufMessage::getStrictValidationVisitor(), message));
    cache_ttl_ = std::chrono::milliseconds(
        PROTOBUF_GET_MS_OR_DEFAULT(message, cache_ttl, DefaultCacheTtl.count()));
  }

  // One cache per worker. Allocated here on the main thread; populated on each
  // worker as it registers.
  tls_->set([](Event::Dispatcher&) { return std::make_shared<ThreadLocalCache>(); });

  // Initialize gRPC channel to the agent's ext_authz server via UDS.
  ext_authz_channel_ = grpc::CreateChannel(
      "unix:./etc/istio/proxy/ext-authz.sock",
      grpc::InsecureChannelCredentials());
  ext_authz_stub_ = envoy::service::auth::v3::Authorization::NewStub(ext_authz_channel_);

  ENVOY_LOG_MISC(info, "[mazu] RBEValidator initialized with ext_authz UDS channel, cache_ttl={}ms",
                 cache_ttl_.count());
}

RBEValidator::~RBEValidator() {
  // Move the map out under the lock, then release the lock before joining: a
  // thread that is mid-`dispatcher->post` must still be able to take the mutex.
  absl::flat_hash_map<uint64_t, Thread::PosixThreadPtr> threads;
  {
    absl::MutexLock lock(&validation_threads_mu_);
    threads = std::move(validation_threads_);
    validation_threads_.clear();
  }
  for (auto& [request_id, thread] : threads) {
    if (thread != nullptr && thread->joinable()) {
      thread->join();
    }
  }

  // Every validation thread has now finished, so nothing else reads
  // `alive_indicator_`. Expiring it here makes any result they already posted a
  // no-op instead of a call into a half-destroyed validator.
  alive_indicator_.reset();
}

std::string RBEValidator::cacheKey(absl::string_view admin_token) {
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t*>(admin_token.data()), admin_token.size(), digest);
  return std::string(reinterpret_cast<const char*>(digest), SHA256_DIGEST_LENGTH);
}

// no need to change: `ca_certs_` will be empty
absl::Status RBEValidator::addClientValidationContext(SSL_CTX* ctx, bool) {
  // Use a generic lambda to be compatible with BoringSSL before and after
  // https://boringssl-review.googlesource.com/c/boringssl/+/56190
  bssl::UniquePtr<STACK_OF(X509_NAME)> list(
      sk_X509_NAME_new([](auto* a, auto* b) -> int { return X509_NAME_cmp(*a, *b); }));

  for (auto& ca : ca_certs_) {
    X509_NAME* name = X509_get_subject_name(ca.get());

    // Check for duplicates.
    if (sk_X509_NAME_find(list.get(), nullptr, name)) {
      continue;
    }

    bssl::UniquePtr<X509_NAME> name_dup(X509_NAME_dup(name));
    if (name_dup == nullptr || !sk_X509_NAME_push(list.get(), name_dup.release())) {
      return absl::InvalidArgumentError("Failed to load trusted client CA certificate");
    }
  }
  SSL_CTX_set_client_CA_list(ctx, list.release());
  return absl::OkStatus();
}

void RBEValidator::updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md,
                                               uint8_t hash_buffer[EVP_MAX_MD_SIZE],
                                               unsigned hash_length) {
  int rc;
  for (auto& ca : ca_certs_) {
    rc = X509_digest(ca.get(), EVP_sha256(), hash_buffer, &hash_length);
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
    RELEASE_ASSERT(hash_length == SHA256_DIGEST_LENGTH,
                   fmt::format("invalid SHA256 hash length {}", hash_length));
    rc = EVP_DigestUpdate(md.get(), hash_buffer, hash_length);
    RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or(""));
  }
}

absl::StatusOr<int> RBEValidator::initializeSslContexts(std::vector<SSL_CTX*>, bool) {
  return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
}



ValidationResults RBEValidator::doVerifyCertChain(
    STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
    const Network::TransportSocketOptionsConstSharedPtr& /*transport_socket_options*/,
    SSL_CTX& /*ctx*/, const CertValidator::ExtraValidationContext& validation_context,
    bool /*is_server*/, absl::string_view /*host_name*/) {

  if (sk_X509_num(&cert_chain) == 0) {
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt,
            "verify cert failed: empty cert chain"};
  }

  if (callback == nullptr) {
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt,
            "verify cert failed: no callback for async validation"};
  }

  X509* leaf_cert = sk_X509_value(&cert_chain, 0);
  ASSERT(leaf_cert);

  // 1. Extract admin token from cert (OID 1.3.6.1.4.1.9901.33) — fast, CPU-only.
  std::string_view admin_token_view =
      Utility::getCertificateExtensionValue(*leaf_cert, AdminTokenOid);
  std::string admin_token = {admin_token_view.begin(), admin_token_view.end()};

  if (admin_token.empty()) {
    stats_.fail_verify_error_.inc();
    ENVOY_LOG_MISC(warn, "[mazu] doVerifyCertChain: admin token not found in cert");
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
            "verify cert failed: admin token extension not found"};
  }

  // 2. Find this worker's cache. `doVerifyCertChain` always runs on a worker
  //    thread, so the slot is expected to be populated; a validator built
  //    without a factory context (tests) has no slot at all.
  OptRef<ThreadLocalCache> cache;
  if (tls_ != nullptr && tls_->currentThreadRegistered()) {
    cache = tls_->get();
  }
  if (!cache.has_value()) {
    stats_.fail_verify_error_.inc();
    ENVOY_LOG_MISC(warn, "[mazu] doVerifyCertChain: no thread-local RBE cache on this thread");
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt,
            "verify cert failed: RBE validator has no thread local state"};
  }

  const std::string cache_key = cacheKey(admin_token);
  const MonotonicTime now = time_source_.monotonicTime();

  // 3. Cached verdict? Both allows and denies are cached, so a rejected peer
  //    cannot re-drive the RPC path on every reconnect. Answering here returns
  //    a non-Pending result, which `ContextImpl::customVerifyCertChain`
  //    completes synchronously — no dispatcher round trip, no RPC.
  if (cache_ttl_.count() > 0) {
    auto it = cache->verdicts_.find(cache_key);
    if (it != cache->verdicts_.end()) {
      if (it->second.expiry_ > now) {
        rbe_stats_->cache_hit_.inc();
        if (it->second.allowed_) {
          return {ValidationResults::ValidationStatus::Successful,
                  Envoy::Ssl::ClientValidationStatus::Validated, absl::nullopt, absl::nullopt};
        }
        // Same shape as the async deny below, so the cache is behaviourally
        // transparent: no extra `ssl.fail_verify_error` for a repeated deny.
        return {ValidationResults::ValidationStatus::Failed,
                Envoy::Ssl::ClientValidationStatus::Failed, SSL_AD_CERTIFICATE_UNKNOWN,
                it->second.error_details_};
      }
      cache->verdicts_.erase(it);
    }
  }

  // 4. Already asking about this token? Attach and wait for the one answer
  //    rather than issuing a second identical RPC (single-flight).
  auto in_flight = cache->in_flight_.find(cache_key);
  if (in_flight != cache->in_flight_.end()) {
    rbe_stats_->coalesced_.inc();
    in_flight->second.waiters_.push_back(std::move(callback));
    return {ValidationResults::ValidationStatus::Pending,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt, absl::nullopt};
  }

  rbe_stats_->cache_miss_.inc();

  // 5. Get remote IP from the connection — fast, in-process. Reported to the
  //    agent for logging only; its verdict is a function of the token alone.
  auto socket_callbacks = validation_context.callbacks;
  auto addr = socket_callbacks->connection().connectionInfoProvider().remoteAddress();
  auto ip_string = addr->ip()->addressAsString();

  Event::Dispatcher& dispatcher = callback->dispatcher();
  const uint64_t request_id = next_request_id_.fetch_add(1, std::memory_order_relaxed);

  // 6. Create managed thread for the blocking gRPC call. It cannot deliver its
  //    result before this function returns: the post lands on this same
  //    worker's dispatcher, which is currently running us.
  Thread::PosixThreadPtr thread = thread_factory_->createThread(
      [this, &dispatcher, key = cache_key, admin_token = std::move(admin_token),
       ip_string = std::move(ip_string), request_id]() mutable -> void {
        performExtAuthzCheck(&dispatcher, std::move(key), std::move(admin_token),
                             std::move(ip_string), request_id);
      },
      Thread::Options{}, /* crash_on_failure=*/false);

  if (thread == nullptr) {
    stats_.fail_verify_error_.inc();
    rbe_stats_->check_failure_.inc();
    ENVOY_LOG_MISC(warn, "[mazu] doVerifyCertChain: failed to create validation thread");
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt,
            "Failed creating a thread for RBE cert validation."};
  }

  {
    absl::MutexLock lock(&validation_threads_mu_);
    validation_threads_[request_id] = std::move(thread);
  }

  PendingRequest pending;
  pending.request_id_ = request_id;
  pending.waiters_.push_back(std::move(callback));
  cache->in_flight_.emplace(cache_key, std::move(pending));

  // 7. Return Pending — worker thread is free to process other connections.
  return {ValidationResults::ValidationStatus::Pending,
          Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt, absl::nullopt};
}

void RBEValidator::performExtAuthzCheck(Event::Dispatcher* dispatcher, std::string cache_key,
                                        std::string admin_token, std::string ip_string,
                                        uint64_t request_id) {
  // Build CheckRequest
  envoy::service::auth::v3::CheckRequest check_req;
  auto* attrs = check_req.mutable_attributes();
  auto* src = attrs->mutable_source();
  src->mutable_address()->mutable_socket_address()->set_address(ip_string);
  auto* http_req = attrs->mutable_request()->mutable_http();
  auto& headers = *http_req->mutable_headers();
  headers["x-rbe-admin-token"] = admin_token;

  // Blocking gRPC call
  envoy::service::auth::v3::CheckResponse check_resp;
  grpc::ClientContext grpc_ctx;
  grpc_ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
  auto status = ext_authz_stub_->Check(&grpc_ctx, check_req, &check_resp);

  bool success = false;
  bool cacheable = true;
  std::string error_details;

  if (!status.ok()) {
    // A transport failure is not a verdict about the peer — do not cache it.
    cacheable = false;
    error_details = fmt::format("RBE ext_authz gRPC error: {}", status.error_message());
    ENVOY_LOG_MISC(warn, "[mazu] validation thread: {}", error_details);
  } else if (check_resp.status().code() != 0) {
    error_details = fmt::format("RBE ext_authz denied: {}", check_resp.status().message());
    ENVOY_LOG_MISC(debug, "[mazu] validation thread: {}", error_details);
  } else {
    success = true;
  }

  // Post result back to the Envoy worker thread with alive guard.
  std::weak_ptr<size_t> weak_alive_indicator(alive_indicator_);

  dispatcher->post([weak_alive_indicator, this, cache_key = std::move(cache_key), request_id,
                    success, cacheable, error_details = std::move(error_details)]() {
    if (weak_alive_indicator.expired()) {
      return;
    }
    onVerificationComplete(cache_key, request_id, success, cacheable, error_details);
  });
}

void RBEValidator::reapValidationThread(uint64_t request_id) {
  Thread::PosixThreadPtr thread;
  {
    absl::MutexLock lock(&validation_threads_mu_);
    auto it = validation_threads_.find(request_id);
    if (it != validation_threads_.end()) {
      thread = std::move(it->second);
      validation_threads_.erase(it);
    }
  }
  // The thread has already posted its result and is on its way out, so this
  // join does not block the event loop for any meaningful time. It only exists
  // because `~PosixThread` asserts the thread was joined.
  if (thread != nullptr && thread->joinable()) {
    thread->join();
  }
}

void RBEValidator::onVerificationComplete(const std::string& cache_key, uint64_t request_id,
                                          bool success, bool cacheable,
                                          const std::string& error_details) {
  reapValidationThread(request_id);

  OptRef<ThreadLocalCache> cache = tls_->get();
  if (!cache.has_value()) {
    return;
  }

  auto node = cache->in_flight_.extract(cache_key);
  if (node.empty()) {
    ENVOY_LOG_MISC(warn, "[mazu] worker thread: no in-flight RBE request for completed check");
    return;
  }
  if (node.mapped().request_id_ != request_id) {
    // A newer request owns this key; leave it alone and drop this stale result.
    cache->in_flight_.insert(std::move(node));
    return;
  }

  if (!cacheable) {
    // A transport-level failure says nothing about the peer; the next handshake
    // must ask again rather than inherit this answer.
    rbe_stats_->check_failure_.inc();
  } else if (cache_ttl_.count() > 0) {
    if (cache->verdicts_.size() >= MaxCacheEntries) {
      const MonotonicTime now = time_source_.monotonicTime();
      absl::erase_if(cache->verdicts_,
                     [now](const auto& entry) { return entry.second.expiry_ <= now; });
      if (cache->verdicts_.size() >= MaxCacheEntries) {
        cache->verdicts_.clear();
      }
    }
    cache->verdicts_[cache_key] =
        CacheEntry{success, error_details, time_source_.monotonicTime() + cache_ttl_};
  }

  // Deliver to every handshake that was waiting on this one answer. Each call
  // resumes a handshake synchronously and may re-enter `doVerifyCertChain`;
  // that is safe because the pending node has already been detached from the
  // map and the verdict is in the cache, so re-entrant lookups hit.
  for (auto& waiter : node.mapped().waiters_) {
    waiter->onCertValidationResult(success,
                                   success ? Envoy::Ssl::ClientValidationStatus::Validated
                                           : Envoy::Ssl::ClientValidationStatus::Failed,
                                   error_details, SSL_AD_CERTIFICATE_UNKNOWN);
  }
}

absl::optional<uint32_t> RBEValidator::daysUntilFirstCertExpires() const {
  if (ca_certs_.empty()) {
    return absl::make_optional(std::numeric_limits<uint32_t>::max());
  }
  absl::optional<uint32_t> ret = absl::make_optional(std::numeric_limits<uint32_t>::max());
  for (auto& cert : ca_certs_) {
    const absl::optional<uint32_t> tmp = Utility::getDaysUntilExpiration(cert.get(), time_source_);
    if (!tmp.has_value()) {
      return absl::nullopt;
    } else if (tmp.value() < ret.value()) {
      ret = tmp;
    }
  }
  return ret;
}

Envoy::Ssl::CertificateDetailsPtr RBEValidator::getCaCertInformation() const {
  if (ca_certs_.empty()) {
    return nullptr;
  }
  // TODO(mathetake): With the current interface, we cannot pass the multiple cert information.
  // So temporarily we return the first CA's info here.
  return Utility::certificateDetails(ca_certs_[0].get(), getCaFileName(), time_source_);
};

class RBEValidatorFactory : public CertValidatorFactory {
public:
  absl::StatusOr<CertValidatorPtr>
  createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
                      Server::Configuration::CommonFactoryContext& context) override {
    return std::make_unique<RBEValidator>(config, stats, context);
  }

  std::string name() const override { return "envoy.tls.cert_validator.rbe"; }
};

REGISTER_FACTORY(RBEValidatorFactory, CertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
