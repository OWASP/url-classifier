package(
    default_visibility = ["//visibility:private"],
)


java_library(
    name = "test_lib",
    srcs = glob(
        include=["*.java"],
        exclude=["*Test.java"],
    ),
    deps = [
        "//java/com/mikesamuel/url",
    ],
    runtime_deps = [
        "@com_google_guava_guava//jar",
        "@junit//jar",
    ],
)

[
    java_test(
        name = test_src[:-5],
        srcs = [test_src],
        size = "small",
        deps = [
            "//java/com/mikesamuel/url",
            "@com_google_guava_guava//jar",
            "@junit//jar",
            ":test_lib",
        ],
    )
    for test_src in glob(["*Test.java"])
]
