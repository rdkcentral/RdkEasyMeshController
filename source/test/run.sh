#!/bin/sh

##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

set -e

print_help_and_exit()
{
    echo "Usage: $0"
    echo "   or  $0 -h"
    echo "   or  $0 [-c] unit[=<test>]|unitcov[=<test>]|unitmem[=<test>]"
    echo ""
    echo "  If no arguments given recompile and run tests"
    echo ""
    echo "  -h               Show this help text."
    echo "  -c               Don't rebuild before running."
    echo "  unit[=<test>]    Run all or specified unit test."
    echo "                   <test> is the test_<test>.c filename in ./test/unit/"
    echo "  unitcov[=<test>] Run all or specified unit tests with code coverage."
    echo "                   Results appear in ./build/agent/src/agent-build/coverage_report*"
    echo "  unitmem[=<test>] Run all or specified unit tests under Valgrind."
    echo "                   Results are also saved in ./build/agent/src/agent-build/test/unit/valgrind-*.xml"
    echo "  validate_schema  Validate all generated json message."
    echo "  log_level=level  Set log level (error, warning, info, debug)"

    exit ${1:-0}
}

# Default
UNITTARGET=test

while [ $# -gt 0 ]
do
    case $1 in
        -c)
            COMPILE_SKIP="YES"
            ;;
        -h)
            print_help_and_exit
            ;;
        unitcov*)
            UNITTEST="${1#unitcov=}"
            if [ "$UNITTEST" != "unitcov" ]; then
                UNITTARGET="unittest_${UNITTEST}_coverage"
            else
                UNITTARGET="test_coverage"
                unset UNITTEST
            fi
            ;;
        unitmem*)
            UNITTEST="${1#unitmem=}"
            if [ "$UNITTEST" != "unitmem" ]; then
                UNITTARGET="unittest_${UNITTEST}_memcheck"
            else
                UNITTARGET="test"
                UNITEXTRA="-D ExperimentalMemCheck"
                unset UNITTEST
            fi
            ;;
        unit*)
            UNITTARGET="test"
            UNITTEST="${1#unit=}"
            if [ "$UNITTEST" != "unit" ]; then
                UNITTEST="_$UNITTEST"
            else
                unset UNITTEST
            fi
            ;;
        validate_schema)
            export UNITTEST_VALIDATE_SCHEMA=1
            ;;
        log_level*)
            export UNITTEST_LOG_LEVEL="${1#log_level=}"
            ;;
        *)
            echo "$1: unknown option"
            print_help_and_exit 1
            ;;
    esac
    shift
done

BUILD_PATH=project/build/tests/src/tests-build

if [ -z "$COMPILE_SKIP" ]; then
    make -C $BUILD_PATH VERBOSE=1
fi

# Remove old valgrind xml files
find $BUILD_PATH -type f -name valgrind*.xml -exec rm {} \;

make -C $BUILD_PATH $UNITTARGET ARGS="--timeout 180 -R unittest$UNITTEST -V ${UNITEXTRA}"

# Check valgrind xml files for errors
for XML in `find $BUILD_PATH -type f -name valgrind*.xml`; do
  ERRORS=`sed -n  '/<error>/,/<\/error>/p' $XML | wc -l`

  if [ "$ERRORS" != "0" ]; then
     EXE=`sed -n '/<args>/,/<\/args>/p' $XML | sed -n '/<argv>/,/<\/argv>/p' | sed -n '/<exe>/,/<\/exe>/p' | sed -e 's/.*<exe>\(.*\)<\/exe>.*/\1/'`
     TEST=`basename $EXE | sed 's/unittest_*//'`
     echo
     echo "WARNING: Valgrind found errors when running test $TEST"
     echo "         Check with ./run.sh unitmem=$TEST"
  fi
done
