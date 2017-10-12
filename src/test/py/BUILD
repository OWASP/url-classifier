package(
    default_visibility = ["//visibility:private"],
)


py_test(
    name = "check_java_identifier_case_test",
    srcs = [
        "check_java_identifier_case.py",
    ],
    main = "check_java_identifier_case.py",
    data = [
        "//src/main/java/org/owasp/url:srcs",
    ]
)


EXTRACTED_SNIPPETS_JAVA = "java/com/example/Snippets.java"

genrule(
    name = "extract_code_snippets_from_docs",
    srcs = ["//:README.md"],
    tools = ["extract_examples.py"],
    outs = [EXTRACTED_SNIPPETS_JAVA],
    cmd = "$(location extract_examples.py) $(SRCS) > $@",
    testonly = 1,
)

java_binary(
    name = "examples",
    srcs = [EXTRACTED_SNIPPETS_JAVA],
    deps = [
        "//src/main/java/org/owasp/url",
    ],
    testonly = 1,
)

sh_test(
    name = "code_snippets_compiled_test",
    srcs = ["code_snippets_compiled_test.sh"],
    data = ["examples.jar"],
)
