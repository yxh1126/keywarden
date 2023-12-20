load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_proto_grpc//cpp:defs.bzl", "cpp_grpc_library")
load("@rules_proto_grpc//python:defs.bzl", "python_grpc_library")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "sign_server_proto",
    srcs = [
        "signserver.proto",
    ],
)

cpp_grpc_library(
    name = "sign_server_cc_grpc",
    protos = [
        ":sign_server_proto",
    ],
)

python_grpc_library(
    name = "sign_server_python_grpc",
    protos = [
        ":sign_server_proto",
    ],
)
