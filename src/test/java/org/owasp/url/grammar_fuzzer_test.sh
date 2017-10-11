#!/bin/bash

# Uses a grammar forcer to generate test cases that exercise the URL parser
# to give some level of confidence that dodgy inputs won't crash the URL
# parser and allow denial of service.

# This test is not repeatable since the fuzzer depends on a PRNG.
# Don't ignore failures if a second run goes green though.

set -e

# Check that we have the environment promised by bazel's sh_test.
[ -n "$TEST_TMPDIR" ]
[ -n "$TEST_SRCDIR" ]

# Check that bazel put runfiles where we expect them
export FUZZER_JAR="$TEST_SRCDIR/gramtest_jar/file/gramtest-0.2.2.jar"
export GRAMMAR_FILE="$TEST_SRCDIR/gramtest_url_bnf/file/url.bnf"
export CONSUMER_JAR="$TEST_SRCDIR/__main__/src/test/java/org/owasp/url/FuzzUrlValue_deploy.jar"

[ -f "$FUZZER_JAR" ]   || (echo "No $FUZZER_JAR";   exit -1)
[ -f "$GRAMMAR_FILE" ] || (echo "No $GRAMMAR_FILE"; exit -1)
[ -f "$CONSUMER_JAR" ] || (echo "No $CONSUMER_JAR"; exit -1)

# Gram tests puts tests, one per file, in a directory.
export GRAM_TESTS_DIR="$TEST_TMPDIR/gramtests"
mkdir -p "$GRAM_TESTS_DIR"

echo Running gramtest
java -jar "$FUZZER_JAR" \
     -num 100 \
     -tests "$GRAM_TESTS_DIR" \
     -file "$GRAMMAR_FILE"

echo
echo Running Tests
java -jar "$CONSUMER_JAR" "$GRAM_TESTS_DIR"/*.txt

echo
echo Have a nice day!
