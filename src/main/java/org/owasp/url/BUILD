package(
    default_visibility = ["//visibility:private"],
)

JAVAC_OPTS = [
    "-target=6",
    "-source=6",
    ]


java_library(
    name = "url",
    srcs = glob(["*.java"]),
    deps = [
        "@com_google_guava_guava//jar",
    ],
    javacopts = JAVAC_OPTS,
    visibility = ["//visibility:public"],
)


filegroup(
    name = "srcs",
    srcs = glob(["*.java"]),
    visibility = [
        "//:__subpackages__",
    ])
