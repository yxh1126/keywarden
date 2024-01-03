package(
    default_visibility = ["//visibility:public"],
)

genrule(
    name = "tool_version_hdr",
    srcs = ["version_hdr.h"],
    outs = ["tool_version.h"],
    tools = ["create_header.sh"],
    cmd = "$(location create_header.sh) $< $@",
    stamp = True,
)

cc_library(
    name = "tool_version",
    hdrs = [":tool_version_hdr"],
)
