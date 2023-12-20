load("@rules_python//python:defs.bzl", "py_binary", "py_library")

package(
    default_visibility = ["//visibility:public"],
)

exports_files([
    "get_public.py",
    "get_signature.py",
    "signserver_pb2_grpc.py",
    "signserver_pb2.py",
    "readme.txt",
])

py_binary(
    name = "get_public",
    srcs = [
        "get_public.py",
    ],
    python_version = "PY3",
)

py_binary(
    name = "get_signature",
    srcs = [
        "get_signature.py",
    ],
    python_version = "PY3",
)
