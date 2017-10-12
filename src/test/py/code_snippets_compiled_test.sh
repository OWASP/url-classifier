#!/bin/bash

set -e

if ! [ -e "$TEST_SRCDIR/__main__/src/test/py/examples.jar" ]; then
    echo "examples.jar not produced"
    exit -1
fi

echo Have a swell day!
