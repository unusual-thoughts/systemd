#!/usr/bin/env bash
set -e
TEST_DESCRIPTION="test Type=any"
. $TEST_BASE_DIR/test-functions

do_test "$@" 59
