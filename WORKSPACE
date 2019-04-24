load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_jar")

maven_jar(
    name = "com_google_guava_guava",
    artifact = "com.google.guava:guava:18.0",
    sha1 = "cce0823396aa693798f8882e64213b1772032b09",
)

maven_jar(
    name = "com_ibm_icu_icu4j",
    artifact = "com.ibm.icu:icu4j:59.1",
    sha1 = "6f06e820cf4c8968bbbaae66ae0b33f6a256b57f",
)

maven_jar(
    name = "junit",
    artifact = "junit:junit:4.12",
)

http_jar(
    name = "gramtest_jar",
    urls = [
        "https://github.com/codelion/gramtest/releases/download/v0.2.2/gramtest-0.2.2.jar",
    ],
    sha256 = "eaedbf8428d9320daa05dbeb2f8682de60f76025e16926e9e2402fd7c4a84f67",
)
