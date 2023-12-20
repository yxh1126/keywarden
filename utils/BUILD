load("@rules_cc//cc:defs.bzl", "cc_library", "cc_binary")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "crypto_utils",
    srcs = [
        "crypto_utils.cc",
    ],
    hdrs = [
        "crypto_utils.h",
    ],
    linkopts = [
        "-lcrypto",
        "-lssl",
    ],
    deps = [
        "//utils:common",
        "//utils:fmt_utils",
    ],
)

cc_library(
    name = "data_utils",
    srcs = [
        "data_utils.cc",
    ],
    hdrs = [
        "data_utils.h",
    ],
    linkopts = [
        "-ljson-c",
    ],
    deps = [
        "//utils:common",
        "//utils:crypto_utils",
        "//utils:fmt_utils",
        "//:glog",
    ],
)

cc_library(
    name = "fmt_utils",
    srcs = [
        "fmt_utils.cc",
    ],
    hdrs = [
        "fmt_utils.h",
    ],
    deps = [
        "//utils:common",
    ],
)

cc_library(
    name = "common",
    hdrs = [
        "common.h",
    ],
)
