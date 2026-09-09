#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/common/time.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/c_smart_ptr.h"
#include "source/common/common/matchers.h"
#include "source/common/common/posix/thread_impl.h"
#include "source/common/common/thread.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/tls/cert_validator/cert_validator.h"
#include "source/common/tls/cert_validator/san_matcher.h"
#include "source/common/tls/stats.h"
#include "source/common/common/logger.h"

#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

#include <grpcpp/grpcpp.h>
#include "envoy/service/auth/v3/external_auth.grpc.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

using X509StorePtr = CSmartPtr<X509_STORE, X509_STORE_free>;

class RBEValidator : public CertValidator, Logger::Loggable<Logger::Id::connection> {
public:
  RBEValidator(SslStats& stats, TimeSource& time_source)
      : stats_(stats), time_source_(time_source){};
  RBEValidator(const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
              Server::Configuration::CommonFactoryContext& context);
  ~RBEValidator() override;

  // Tls::CertValidator
  absl::Status addClientValidationContext(SSL_CTX* context, bool require_client_cert) override;

  ValidationResults
  doVerifyCertChain(STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
                    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                    SSL_CTX& ssl_ctx,
                    const CertValidator::ExtraValidationContext& validation_context, bool is_server,
                    absl::string_view host_name) override;

  absl::StatusOr<int> initializeSslContexts(std::vector<SSL_CTX*> contexts,
                                            bool provides_certificates) override;

  void updateDigestForSessionId(bssl::ScopedEVP_MD_CTX& md, uint8_t hash_buffer[EVP_MAX_MD_SIZE],
                                unsigned hash_length) override;

  absl::optional<uint32_t> daysUntilFirstCertExpires() const override;
  std::string getCaFileName() const override { return ca_file_name_; }
  Envoy::Ssl::CertificateDetailsPtr getCaCertInformation() const override;

  // Utility functions
  X509_STORE* getTrustBundleStore(X509* leaf_cert);
  static std::string extractTrustDomain(const std::string& san);
  static bool certificatePrecheck(X509* leaf_cert);
  absl::flat_hash_map<std::string, X509StorePtr>& trustBundleStores() {
    return trust_bundle_stores_;
  };

  bool matchSubjectAltName(X509& leaf_cert);

  // Default validation-verdict cache TTL. Must stay <= the agent's
  // `tokenCacheTTL` so this validator never serves a verdict the agent would
  // itself have refreshed.
  static constexpr std::chrono::milliseconds DefaultCacheTtl{1000};

  // Upper bound on cached verdicts per worker. Only exists to keep the map from
  // growing without bound if peer identities churn; the steady-state size is
  // the number of distinct peer pods (tens).
  static constexpr size_t MaxCacheEntries = 1024;

private:
  // A verdict from a completed ext_authz Check, reusable until `expiry_`.
  // Denies are cached as well as allows, so a rejected peer cannot re-drive the
  // full validation path on every reconnect.
  struct CacheEntry {
    bool allowed_;
    std::string error_details_;
    MonotonicTime expiry_;
  };

  // The handshakes waiting on one in-flight ext_authz Check. Concurrent
  // handshakes presenting the same admin token attach here instead of issuing
  // their own RPC (single-flight).
  struct PendingRequest {
    std::vector<Ssl::ValidateResultCallbackPtr> waiters_;
    uint64_t request_id_{0};
  };

  // Per-worker cache and in-flight table. Both are only ever touched from the
  // owning worker thread, so neither needs a lock: `doVerifyCertChain` runs on
  // the worker, and completions are posted back to that same worker's
  // dispatcher.
  struct ThreadLocalCache : public ThreadLocal::ThreadLocalObject {
    absl::flat_hash_map<std::string, CacheEntry> verdicts_;
    absl::flat_hash_map<std::string, PendingRequest> in_flight_;
  };

  struct RBEStats {
    RBEStats(Stats::Scope& scope)
        : cache_hit_(scope.counterFromString("cache_hit")),
          cache_miss_(scope.counterFromString("cache_miss")),
          coalesced_(scope.counterFromString("coalesced")),
          check_failure_(scope.counterFromString("check_failure")) {}

    // A handshake answered from the per-worker verdict cache, with no RPC.
    Stats::Counter& cache_hit_;
    // A handshake that had to issue an ext_authz Check.
    Stats::Counter& cache_miss_;
    // A handshake attached to another handshake's in-flight Check.
    Stats::Counter& coalesced_;
    // A Check that failed at the transport level (as opposed to returning a
    // deny verdict) — gRPC error, deadline, thread-creation failure.
    Stats::Counter& check_failure_;
  };

  // The cache key: SHA-256 of the peer's admin token. The agent's
  // `checkWithToken()` derives its answer from the token alone and ignores the
  // source address, so the token is the complete input to the verdict.
  static std::string cacheKey(absl::string_view admin_token);

  void performExtAuthzCheck(Event::Dispatcher* dispatcher, std::string cache_key,
                            std::string admin_token, std::string ip_string, uint64_t request_id);
  // `cacheable` is false when the Check failed at the transport level (gRPC
  // error or deadline). Such a result is delivered to the waiters but never
  // stored, so the next handshake retries instead of inheriting a non-verdict.
  void onVerificationComplete(const std::string& cache_key, uint64_t request_id, bool success,
                              bool cacheable, const std::string& error_details);

  // Joins and drops the validation thread for `request_id`, if it is still
  // registered. Called on the worker once the thread has posted its result.
  void reapValidationThread(uint64_t request_id);

  bool verifyCertChainUsingTrustBundleStore(X509& leaf_cert, STACK_OF(X509)* cert_chain,
                                            X509_VERIFY_PARAM* verify_param,
                                            std::string& error_details);

  bool allow_expired_certificate_{false};
  std::vector<bssl::UniquePtr<X509>> ca_certs_;
  std::string ca_file_name_;
  std::vector<SanMatcherPtr> subject_alt_name_matchers_{};
  absl::flat_hash_map<std::string, X509StorePtr> trust_bundle_stores_;

  std::shared_ptr<grpc::Channel> ext_authz_channel_;
  std::unique_ptr<envoy::service::auth::v3::Authorization::Stub> ext_authz_stub_;

  // Per-worker verdict cache and single-flight table. Null for the
  // stats-and-time-source-only constructor used by tests.
  ThreadLocal::TypedSlotPtr<ThreadLocalCache> tls_;
  std::chrono::milliseconds cache_ttl_{DefaultCacheTtl};

  // Owns the in-flight validation threads purely so that they can be joined —
  // `~PosixThread` asserts the thread was joined and there is no detach. This
  // is touched once per *cache miss*, not once per handshake, so the lock is
  // off the hot path. It disappears entirely with the async-client rework.
  mutable absl::Mutex validation_threads_mu_;
  absl::flat_hash_map<uint64_t, Thread::PosixThreadPtr> validation_threads_
      ABSL_GUARDED_BY(validation_threads_mu_);
  std::atomic<uint64_t> next_request_id_{0};

  std::shared_ptr<size_t> alive_indicator_{new size_t(1)};
  Thread::PosixThreadFactoryPtr thread_factory_;

  Stats::ScopeSharedPtr rbe_scope_;
  std::unique_ptr<RBEStats> rbe_stats_;
  SslStats& stats_;
  TimeSource& time_source_;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
