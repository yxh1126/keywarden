load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_test(
    name = "test_rpc_sign_client",
    srcs = [
        "test_rpc_sign_client.cc"
    ],
    data = [
        "//data:hashlist.txt",
        "//data:hashlist_ex.txt",
    ],
    deps = [
        "//:gtest",
        "//client/common:rpc_sign_client",
    ],
)
