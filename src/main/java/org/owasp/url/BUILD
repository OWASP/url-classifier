package(
    default_visibility = ["//visibility:private"],
)


java_library(
    name = "url",
    srcs = glob(["*.java"]),
    deps = [
        "@com_google_guava_guava//jar",
    ],
    visibility = ["//visibility:public"],
)


filegroup(
    name = "srcs",
    srcs = glob(["*.java"]),
    visibility = [
        "//:__subpackages__",
    ])
