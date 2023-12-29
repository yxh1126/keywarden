load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "rpc_sign_client",
    srcs = [
        "rpc_sign_client.cc",
    ],
    hdrs = [
        "rpc_sign_client.h",
    ],
    deps = [
        "//protos:sign_server_cc_grpc",
        "//utils:crypto_utils",
        "//utils:fmt_utils",
        "//utils:common",
    ],
)
