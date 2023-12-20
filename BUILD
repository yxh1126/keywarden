load("@rules_pkg//:pkg.bzl", "pkg_tar", "pkg_deb")

package(
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "rpc_client_list",
    srcs = [
        "//client/cpp:get_public",
        "//client/cpp:get_signature",
    ],
)

filegroup(
    name = "rpc_py_client_list",
    data = [
        "//client/python:get_public.py",
        "//client/python:get_signature.py",
        "//client/python:signserver_pb2_grpc.py",
        "//client/python:signserver_pb2.py",
        "//client/python:readme.txt",
    ],
)

pkg_tar(
    name = "client_tools",
    srcs = [
        "rpc_client_list",
    ],
    extension = "tar.gz",
    include_runfiles = 1,
    mode = "0755",
    strip_prefix = ".",
    package_dir = "/bin",
)

pkg_tar(
    name = "client_python_tools",
    srcs = [
        "rpc_py_client_list",
    ],
    extension = "tar.gz",
    include_runfiles = 1,
    mode = "0755",
    strip_prefix = ".",
)

pkg_tar(
    name = "server_launcher",
    srcs = [
        "//server:run_server",
    ],
    extension = "tar.gz",
    include_runfiles = 1,
    mode = "0755",
    strip_prefix = ".",
    package_dir = "/bin",
)

alias(
    name = "boost",
    actual = "@boost//:program_options",
)

alias(
    name = "gtest",
    actual = "@com_google_googletest//:gtest_main",
)

alias(
    name = "glog",
    actual = "@com_github_google_glog//:glog",
)
