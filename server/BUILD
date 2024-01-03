load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "rpc_sign_server",
    srcs = [
        "rpc_sign_server.cc",
    ],
    hdrs = [
        "rpc_sign_server.h",
    ],
    deps = [
        "//utils:data_utils",
        "//protos:sign_server_cc_grpc",
    ],
)

cc_binary(
    name = "run_server",
    srcs = [
        "run_server.cc",
    ],
    data = [
        "//data:server.db",
    ],
    deps = [
        "//server:rpc_sign_server",
        "//utils:common",
        "//version:tool_version",
        "//:boost",
        "//:glog",
    ],
)
