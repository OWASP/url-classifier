package(
    default_visibility = ["//visibility:private"],
)


java_library(
    name = "test_lib",
    srcs = glob(
        include=["*.java"],
        exclude=["*Test.java", "FuzzUrlValue.java"],
    ),
    deps = [
        "//src/main/java/org/owasp/url",
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
            "//src/main/java/org/owasp/url",
            "@com_google_guava_guava//jar",
            "@junit//jar",
            ":test_lib",
        ],
    )
    for test_src in glob(["*Test.java"])
]


sh_test(
    name = "all_tests_annotated",
    srcs = ["all_tests_annotated.sh"],
    data = glob(["*Test.java"]),
)


java_binary(
    name = "FuzzUrlValue",
    srcs = [
        "FuzzUrlValue.java",
    ],
    deps = [
        "//src/main/java/org/owasp/url",
        "@com_google_guava_guava//jar",
    ],
    testonly = 1,
)

sh_test(
    name = "grammar_fuzzer_test",
    srcs = ["grammar_fuzzer_test.sh"],
    data = [
        "@gramtest_jar//jar",
        "url.bnf",
        "FuzzUrlValue_deploy.jar",
    ],
)
