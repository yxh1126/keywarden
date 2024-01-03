load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_binary(
    name = "get_public",
    srcs = [
        "get_public.cc",
    ],
    deps = [
        "//client/common:rpc_sign_client",
        "//utils:common",
        "//version:tool_version",
        "//:boost",
    ],
)

cc_binary(
    name = "get_signature",
    srcs = [
        "get_signature.cc",
    ],
    deps = [
        "//client/common:rpc_sign_client",
        "//utils:fmt_utils",
        "//utils:crypto_utils",
        "//utils:common",
        "//version:tool_version",
        "//:boost",
    ],
)
