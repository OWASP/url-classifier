#!/bin/bash

set -e

# Check that there the same number of @Test annotations
# is the same as the number of "void test" methods in each
# of *Test.java
[ -n "$TEST_SRCDIR" ]
[ -n "$TEST_TMPDIR" ]

find -L "$TEST_SRCDIR" -name \*Test.java \
     | xargs egrep 'void test' -c \
     | sort > "$TEST_TMPDIR"/unit_test_methods.txt

find -L "$TEST_SRCDIR" -name \*Test.java \
     | xargs egrep '@Test' -c \
     | sort > "$TEST_TMPDIR"/unit_test_annotations.txt

diff "$TEST_TMPDIR"/unit_test_methods.txt \
     "$TEST_TMPDIR"/unit_test_annotations.txt
