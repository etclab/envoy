#include "source/extensions/transport_sockets/tls/cert_validator/rbe/rbe_validator.h"

#include <openssl/safestack.h>

#include <chrono>
#include <cstdint>
#include <openssl/x509.h>
#include <sstream>

#include "envoy/extensions/transport_sockets/tls/v3/common.pb.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls_rbe_validator_config.pb.h"
#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/ssl_socket_extended_info.h"

#include "source/common/config/datasource.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
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

const Envoy::Ssl::CertificateValidationContextConfig* certificateConfig;

RBEValidator::RBEValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                 SslStats& stats,
                                 Server::Configuration::CommonFactoryContext& context)
    : stats_(stats), time_source_(context.timeSource()) {
  ASSERT(config != nullptr);
  certificateConfig = config;

  // Initialize gRPC channel to the agent's ext_authz server via UDS.
  ext_authz_channel_ = grpc::CreateChannel(
      "unix:./etc/istio/proxy/ext-authz.sock",
      grpc::InsecureChannelCredentials());
  ext_authz_stub_ = envoy::service::auth::v3::Authorization::NewStub(ext_authz_channel_);

  ENVOY_LOG_MISC(info, "[mazu] RBEValidator initialized with ext_authz UDS channel");
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
    STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr /*callback*/,
    const Network::TransportSocketOptionsConstSharedPtr& /*transport_socket_options*/,
    SSL_CTX& /*ctx*/, const CertValidator::ExtraValidationContext& validation_context,
    bool /*is_server*/, absl::string_view /*host_name*/) {

  if (sk_X509_num(&cert_chain) == 0) {
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt,
            "verify cert failed: empty cert chain"};
  }

  X509* leaf_cert = sk_X509_value(&cert_chain, 0);
  ASSERT(leaf_cert);

  // 1. Extract admin token from cert (OID 1.3.6.1.4.1.9901.33)
  constexpr absl::string_view admin_token_oid = "1.3.6.1.4.1.9901.33";
  std::string_view admin_token_view = Utility::getCertificateExtensionValue(*leaf_cert, admin_token_oid);
  std::string admin_token = {admin_token_view.begin(), admin_token_view.end()};

  if (admin_token.empty()) {
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
            "verify cert failed: admin token extension not found"};
  }

  // 2. Get remote IP from the connection
  auto socket_callbacks = validation_context.callbacks;
  auto addr = socket_callbacks->connection().connectionInfoProvider().remoteAddress();
  auto ip_string = addr->ip()->addressAsString();

  ENVOY_LOG_MISC(info, "[mazu] doVerifyCertChain: calling ext_authz for ip={}", ip_string);

  // 3. Build CheckRequest — send IP + token directly, no cert
  envoy::service::auth::v3::CheckRequest check_req;
  auto* attrs = check_req.mutable_attributes();
  auto* src = attrs->mutable_source();
  src->mutable_address()->mutable_socket_address()->set_address(ip_string);

  auto* http_req = attrs->mutable_request()->mutable_http();
  auto& headers = *http_req->mutable_headers();
  headers["x-rbe-admin-token"] = admin_token;

  // 4. Synchronous gRPC call to ext_authz via UDS
  envoy::service::auth::v3::CheckResponse check_resp;
  grpc::ClientContext grpc_ctx;
  grpc_ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
  auto status = ext_authz_stub_->Check(&grpc_ctx, check_req, &check_resp);

  if (!status.ok()) {
    ENVOY_LOG_MISC(warn, "[mazu] doVerifyCertChain: ext_authz gRPC call failed: {}",
                   status.error_message());
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
            "RBE validation failed: ext_authz gRPC error"};
  }

  if (check_resp.status().code() != 0) {
    ENVOY_LOG_MISC(warn, "[mazu] doVerifyCertChain: ext_authz denied: {}",
                   check_resp.status().message());
    stats_.fail_verify_error_.inc();
    return {ValidationResults::ValidationStatus::Failed,
            Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
            "RBE validation failed via ext_authz"};
  }

  ENVOY_LOG_MISC(info, "[mazu] doVerifyCertChain: RBE validation passed for ip={}", ip_string);
  return {ValidationResults::ValidationStatus::Successful,
          Envoy::Ssl::ClientValidationStatus::Validated, absl::nullopt,
          absl::nullopt};
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
