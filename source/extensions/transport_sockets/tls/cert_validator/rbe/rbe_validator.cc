#include "source/extensions/transport_sockets/tls/cert_validator/rbe/rbe_validator.h"

#include <openssl/safestack.h>

#include <cstdint>
#include <openssl/x509.h>
#include <sstream>
#include <fstream>
#include <typeinfo>
#include <nlohmann/json.hpp>

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

extern "C" {
#include <kubernetes/config/kube_config.h>
#include <kubernetes/config/incluster_config.h>
#include <kubernetes/api/AuthenticationV1API.h>
#include <kubernetes/model/v1_token_review_spec.h>
#include <kubernetes/model/v1_token_review.h>
}

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
  ENVOY_LOG_MISC(info, "[mazu] Inside of RBEValidator::RBEValidator");
  
  ASSERT(config != nullptr);

  certificateConfig = config;

  // RBEConfig rbeConfig;
  // THROW_IF_NOT_OK(Config::Utility::translateOpaqueConfig(
  //     certificateConfig->customValidatorConfig().value().typed_config(),
  //     ProtobufMessage::getStrictValidationVisitor(), rbeConfig));

  // ENVOY_LOG_MISC(info, "[mazu] Initial RBE Config: {}", rbeConfig.DebugString());

  // auto json_str = THROW_OR_RETURN_VALUE(
  //   Config::DataSource::read(rbeConfig.pod_validity_map(), true, certificateConfig->api()), std::string);

  // auto json_obj = nlohmann::json::parse(json_str);
  // for (auto& el : json_obj.items()) {
  //   pod_validity_map_[el.key()] = el.value().get<bool>();
  // }

  // ENVOY_LOG_MISC(info, "[mazu] Initial Pod Validity Map: {}", pod_validity_map_);
}

// old constructor
// RBEValidator::RBEValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
//                                  SslStats& stats,
//                                  Server::Configuration::CommonFactoryContext& context)
//     : stats_(stats), time_source_(context.timeSource()) {
//   ASSERT(config != nullptr);
//   allow_expired_certificate_ = config->allowExpiredCertificate();

//   RBEConfig message;
//   THROW_IF_NOT_OK(Config::Utility::translateOpaqueConfig(
//       config->customValidatorConfig().value().typed_config(),
//       ProtobufMessage::getStrictValidationVisitor(), message));

//   auto random_strings_list = message.random_strings();
//   std::stringstream random_values;
//   for (const auto& random_string : random_strings_list) {
//     random_values << random_string.value() << ", ";
//   }
//   ENVOY_LOG_MISC(info, "[mazu] logging random values: {}", random_values.str());

//   if (!config->subjectAltNameMatchers().empty()) {
//     for (const auto& matcher : config->subjectAltNameMatchers()) {
//       if (matcher.san_type() ==
//           envoy::extensions::transport_sockets::tls::v3::SubjectAltNameMatcher::URI) {
//         // Only match against URI SAN since SPIFFE specification does not restrict values in other
//         // SAN types. See the discussion: https://github.com/envoyproxy/envoy/issues/15392
//         // TODO(pradeepcrao): Throw an exception when a non-URI matcher is encountered after the
//         // deprecated field match_subject_alt_names is removed
//         subject_alt_name_matchers_.emplace_back(createStringSanMatcher(matcher, context));
//       }
//     }
//   }

//   const auto size = message.trust_domains().size();
//   trust_bundle_stores_.reserve(size);
//   for (auto& domain : message.trust_domains()) {
//     if (trust_bundle_stores_.find(domain.name()) != trust_bundle_stores_.end()) {
//       throw EnvoyException(absl::StrCat(
//           "Multiple trust bundles are given for one trust domain for ", domain.name()));
//     }

//     auto cert = THROW_OR_RETURN_VALUE(
//         Config::DataSource::read(domain.trust_bundle(), true, config->api()), std::string);
//     bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(cert.data()), cert.size()));
//     RELEASE_ASSERT(bio != nullptr, "");
//     bssl::UniquePtr<STACK_OF(X509_INFO)> list(
//         PEM_X509_INFO_read_bio(bio.get(), nullptr, nullptr, nullptr));
//     if (list == nullptr || sk_X509_INFO_num(list.get()) == 0) {
//       throw EnvoyException(
//           absl::StrCat("Failed to load trusted CA certificate for ", domain.name()));
//     }

//     auto store = X509StorePtr(X509_STORE_new());
//     bool has_crl = false;
//     bool ca_loaded = false;
//     for (const X509_INFO* item : list.get()) {
//       if (item->x509) {
//         X509_STORE_add_cert(store.get(), item->x509);
//         ca_certs_.push_back(bssl::UniquePtr<X509>(item->x509));
//         X509_up_ref(item->x509);
//         if (!ca_loaded) {
//           // TODO: With the current interface, we cannot return the multiple
//           // cert information on getCaCertInformation method.
//           // So temporarily we return the first CA's info here.
//           ca_loaded = true;
//           ca_file_name_ = absl::StrCat(domain.name(), ": ",
//                                        domain.trust_bundle().filename().empty()
//                                            ? "<inline>"
//                                            : domain.trust_bundle().filename());
//         }
//       }

//       if (item->crl) {
//         has_crl = true;
//         X509_STORE_add_crl(store.get(), item->crl);
//       }
//     }
//     if (has_crl) {
//       X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
//     }
//     trust_bundle_stores_[domain.name()] = std::move(store);
//   }
// }

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

// no need to change: `ca_certs_` will be empty
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

// no need to change
absl::StatusOr<int> RBEValidator::initializeSslContexts(std::vector<SSL_CTX*>, bool) {
  return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
}

// skipped -- locally defined
// bool RBEValidator::verifyCertChainUsingTrustBundleStore(X509& leaf_cert,
//                                                            STACK_OF(X509)* cert_chain,
//                                                            X509_VERIFY_PARAM* verify_param,
//                                                            std::string& error_details) {
//   // what does precheck do?                                                            
//   if (!RBEValidator::certificatePrecheck(&leaf_cert)) {
//     error_details = "verify cert failed: cert precheck";
//     stats_.fail_verify_error_.inc();
//     return false;
//   }

//   auto trust_bundle = getTrustBundleStore(&leaf_cert);
//   if (!trust_bundle) {
//     error_details = "verify cert failed: no trust bundle store";
//     stats_.fail_verify_error_.inc();
//     return false;
//   }

//   // Set the trust bundle's certificate store on a copy of the context, and do the verification.
//   bssl::UniquePtr<X509_STORE_CTX> new_store_ctx(X509_STORE_CTX_new());
//   if (!X509_STORE_CTX_init(new_store_ctx.get(), trust_bundle, &leaf_cert, cert_chain) ||
//       !X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(new_store_ctx.get()), verify_param)) {
//     error_details = "verify cert failed: init and setup X509_STORE_CTX";
//     stats_.fail_verify_error_.inc();
//     return false;
//   }
//   if (allow_expired_certificate_) {
//     CertValidatorUtil::setIgnoreCertificateExpiration(new_store_ctx.get());
//   }
//   auto ret = X509_verify_cert(new_store_ctx.get());
//   if (!ret) {
//     error_details = absl::StrCat("verify cert failed: ",
//                                  Utility::getX509VerificationErrorInfo(new_store_ctx.get()));
//     stats_.fail_verify_error_.inc();
//     return false;
//   }

//   // Do SAN matching.
//   const bool san_match = subject_alt_name_matchers_.empty() ? true : matchSubjectAltName(leaf_cert);
//   if (!san_match) {
//     error_details = "verify cert failed: SAN match";
//     stats_.fail_verify_san_.inc();
//   }
//   return san_match;
// }

class KubernetesClient {
private:
    char* basePath;
    sslConfig_t* sslConfig;
    list_t* apiKeys;
    apiClient_t* apiClient;

public:
    KubernetesClient() : basePath(nullptr), sslConfig(nullptr), apiKeys(nullptr), apiClient(nullptr) {
        int rc = load_incluster_config(&basePath, &sslConfig, &apiKeys);
        if (rc != 0) {
            throw std::runtime_error("Cannot load kubernetes configuration in cluster.");
        }

        apiClient = apiClient_create_with_base_path(basePath, sslConfig, apiKeys);
        if (!apiClient) {
            free_client_config(basePath, sslConfig, apiKeys);
            throw std::runtime_error("Cannot create kubernetes client.");
        }
    }

    ~KubernetesClient() {
        if (apiClient) {
            apiClient_free(apiClient);
        }
        free_client_config(basePath, sslConfig, apiKeys);
        apiClient_unsetupGlobalEnv();
    }

    std::string validateSvcAccountToken(std::string token, const std::string& namespaceName = "default") {
        // Create a non-const copy of the namespace string
        char* namespace_copy = strdup(namespaceName.c_str());
        if (!namespace_copy) {
            throw std::runtime_error("Memory allocation failed");
        }

        char *c_token = strdup(token.c_str());
        v1_token_review_spec_t *spec = v1_token_review_spec_create(NULL, c_token);
        
        v1_token_review_t *token_review = v1_token_review_create(NULL, NULL, NULL, spec, NULL);

        v1_token_review_t *result = AuthenticationV1API_createTokenReview(apiClient, token_review, NULL, NULL, NULL, NULL);

        // Clean up
        v1_token_review_free(token_review);
        free(namespace_copy);

        return result && result->status && result->status->authenticated ? result->status->user->username : "";
    }
};

// overridden
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

  RBEConfig rbeConfig;
  THROW_IF_NOT_OK(Config::Utility::translateOpaqueConfig(
      certificateConfig->customValidatorConfig().value().typed_config(),
      ProtobufMessage::getStrictValidationVisitor(), rbeConfig));

  ENVOY_LOG_MISC(info, "[mazu] Updated RBE Config: {}", rbeConfig.DebugString());

  auto json_str = THROW_OR_RETURN_VALUE(
    Config::DataSource::read(rbeConfig.pod_validity_map(), true, certificateConfig->api()), std::string);

  auto json_obj = nlohmann::json::parse(json_str);
  for (auto& el : json_obj.items()) {
    pod_validity_map_[el.key()] = el.value().get<bool>();
  }
  ENVOY_LOG_MISC(info, "[mazu] Updated Pod Validity Map: {}", pod_validity_map_);

  constexpr absl::string_view admin_token_oid = "1.3.6.1.4.1.9901.33";
  std::string_view admin_token_view = Utility::getCertificateExtensionValue(*leaf_cert, admin_token_oid);
  std::string admin_token = {admin_token_view.begin(), admin_token_view.end()};
  ENVOY_LOG_MISC(info, "[mazu] Admin token: {}", admin_token);

  std::string username;

  try {
    KubernetesClient client;
    username = client.validateSvcAccountToken(admin_token);

    if (username.empty()) {
      return ValidationResults{ValidationResults::ValidationStatus::Failed,
                                      Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
                                      "verify cert failed: invalid admin token"};
    }
  } catch (const std::exception& e) {
    return ValidationResults{ValidationResults::ValidationStatus::Failed,
                                      Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
                                      "verify cert failed: error validating admin token"};
  }

  ENVOY_LOG_MISC(info, "[mazu] Admin Token Username: {}", username);

  constexpr absl::string_view spiffe_id_oid = "1.3.6.1.4.1.9901.34";
  std::string_view spiffe_id = Utility::getCertificateExtensionValue(*leaf_cert, spiffe_id_oid);
  std::string spiffe_id_str = {spiffe_id.begin(), spiffe_id.end()};

  auto socket_callbacks = validation_context.callbacks;
  auto addr = socket_callbacks->connection().connectionInfoProvider().remoteAddress();
  auto port = addr->ip()->port();
  auto ip_string = addr->ip()->addressAsString();

  std::string pod_key = ip_string + "|" + std::to_string(port) + "|" + admin_token;

  if (pod_validity_map_.find(pod_key) == pod_validity_map_.end()) {
    ENVOY_LOG_MISC(info, "[mazu] no entry found for key: {}", pod_key);
  } else {
    ENVOY_LOG_MISC(info, "[mazu] found entry for key: {}", pod_key);
    if (pod_validity_map_[pod_key] == true) {
      ENVOY_LOG_MISC(info, "[mazu] pod is valid {} and pod_key is {}", pod_validity_map_[pod_key], pod_key);
      return ValidationResults{ValidationResults::ValidationStatus::Successful,
                                      Envoy::Ssl::ClientValidationStatus::Validated, absl::nullopt,
                                      absl::nullopt};
    }
  }

  // TODO: how would the new updates to rbe id change this?
  ENVOY_LOG_MISC(info, "[mazu] pod with key {} is invalid", pod_key);
  return ValidationResults{ValidationResults::ValidationStatus::Failed,
                                      Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt,
                                      "verify cert failed: invalid pod"};
}

// local
// X509_STORE* RBEValidator::getTrustBundleStore(X509* leaf_cert) {
//   bssl::UniquePtr<GENERAL_NAMES> san_names(static_cast<GENERAL_NAMES*>(
//       X509_get_ext_d2i(leaf_cert, NID_subject_alt_name, nullptr, nullptr)));
//   if (!san_names) {
//     return nullptr;
//   }

//   std::string trust_domain;
//   for (const GENERAL_NAME* general_name : san_names.get()) {
//     if (general_name->type != GEN_URI) {
//       continue;
//     }

//     const std::string san = Utility::generalNameAsString(general_name);
//     trust_domain = RBEValidator::extractTrustDomain(san);
//     // We can assume that valid SVID has only one URI san.
//     break;
//   }

//   if (trust_domain.empty()) {
//     return nullptr;
//   }

//   auto target_store = trust_bundle_stores_.find(trust_domain);
//   return target_store != trust_bundle_stores_.end() ? target_store->second.get() : nullptr;
// }

// local
// bool RBEValidator::certificatePrecheck(X509* leaf_cert) {
//   // Check basic constrains and key usage.
//   // https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md#52-leaf-validation
//   const auto ext = X509_get_extension_flags(leaf_cert);
//   if (ext & EXFLAG_CA) {
//     return false;
//   }

//   const auto us = X509_get_key_usage(leaf_cert);
//   return (us & (KU_CRL_SIGN | KU_KEY_CERT_SIGN)) == 0;
// }

// local
// bool RBEValidator::matchSubjectAltName(X509& leaf_cert) {
//   bssl::UniquePtr<GENERAL_NAMES> san_names(static_cast<GENERAL_NAMES*>(
//       X509_get_ext_d2i(&leaf_cert, NID_subject_alt_name, nullptr, nullptr)));
//   // We must not have san_names == nullptr here because this function is called after the
//   // SPIFFE cert validation algorithm succeeded, which requires exactly one URI SAN in the leaf
//   // cert.
//   ASSERT(san_names != nullptr,
//          "san_names should have at least one name after SPIFFE cert validation");

//   for (const GENERAL_NAME* general_name : san_names.get()) {
//     for (const auto& config_san_matcher : subject_alt_name_matchers_) {
//       if (config_san_matcher->match(general_name)) {
//         return true;
//       }
//     }
//   }
//   return false;
// }

// local
// std::string RBEValidator::extractTrustDomain(const std::string& san) {
//   static const std::string prefix = "spiffe://";
//   if (!absl::StartsWith(san, prefix)) {
//     return "";
//   }

//   auto pos = san.find('/', prefix.size());
//   if (pos != std::string::npos) {
//     return san.substr(prefix.size(), pos - prefix.size());
//   }
//   return "";
// }

// no need to change - `ca_certs_` will be empty
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

// overridden
Envoy::Ssl::CertificateDetailsPtr RBEValidator::getCaCertInformation() const {
  if (ca_certs_.empty()) {
    return nullptr;
  }
  // TODO(mathetake): With the current interface, we cannot pass the multiple cert information.
  // So temporarily we return the first CA's info here.
  return Utility::certificateDetails(ca_certs_[0].get(), getCaFileName(), time_source_);
};

// probably for registring the validator 
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
