load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_test(
    name = "test_crypto_utils",
    srcs = [
        "test_crypto_utils.cc"
    ],
    data = [
        "//data:server.db",
        "//data:server.txt",
        "//data:textfile.txt",
    ],
    deps = [
        "//:gtest",
        "//utils:common",
        "//utils:fmt_utils",
        "//utils:crypto_utils",
    ],
)

cc_test(
    name = "test_data_utils",
    srcs = [
        "test_data_utils.cc"
    ],
    data = [
        "//data:server.db",
    ],
    deps = [
        "//:gtest",
        "//utils:common",
        "//utils:data_utils",
    ],
)

cc_test(
    name = "test_fmt_utils",
    srcs = [
        "test_fmt_utils.cc"
    ],
    data = [
        "//data:hexdata.bin",
        "//data:hexdata.txt",
    ],
    deps = [
        "//:gtest",
        "//utils:common",
        "//utils:fmt_utils",
    ],
)
