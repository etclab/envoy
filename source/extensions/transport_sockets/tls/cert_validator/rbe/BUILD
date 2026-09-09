load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "config",
    srcs = [
        "rbe_validator.cc",
    ],
    hdrs = [
        "rbe_validator.h",
    ],
    external_deps = ["ssl",],
    deps = [
        "//envoy/ssl:context_config_interface",
        "//envoy/ssl:ssl_socket_extended_info_interface",
        "//envoy/stats:stats_interface",
        "//envoy/thread:thread_interface",
        "//envoy/thread_local:thread_local_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:c_smart_ptr_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:utility_lib",
        "//source/common/common:thread_impl_lib_posix",
        "//source/common/config:datasource_lib",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:message_validator_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/stats:symbol_table_lib",
        "//source/common/stats:utility_lib",
        "//source/common/common:logger_lib",
        "//source/common/tls:stats_lib",
        "//source/common/tls:utility_lib",
        "//source/common/tls/cert_validator:cert_validator_lib",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/synchronization",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@boringssl//:ssl"
    ],
)
