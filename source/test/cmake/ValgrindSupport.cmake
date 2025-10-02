##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

# The source code form of this Open Source Project components
# is subject to the terms of the Clear BSD license.
# You can redistribute it and/or modify it under the terms of the
# Clear BSD License (http://directory.fsf.org/wiki/License:ClearBSD)
# See COPYING file/LICENSE file for more details.
# This software project does also include third party Open Source Software:
# See COPYING file/LICENSE file for more details.

# Support for Valgrind
find_program(VALGRIND_EXEC valgrind)
if (DEFINED VALGRIND_EXEC)
    message(STATUS "Found Valgrind: ${VALGRIND_EXEC}")
    set(CTEST_MEMORYCHECK_COMMAND ${VALGRIND_EXEC})
    set(SUPPRESSIONS_FILE "${PROJECT_SOURCE_DIR}/suppressions.vg" )
    # Valgrind settings for interactive use
    set(MEMORYCHECK_DEV_COMMAND_OPTIONS --trace-children=no --num-callers=50 --leak-check=full --show-reachable=yes --track-origins=yes --suppressions=${SUPPRESSIONS_FILE})
    # Valgrind settings for Jenkins' Valgrind plug-in
    set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=no --num-callers=50 --leak-check=full --show-reachable=yes --track-origins=yes --xml=yes --xml-file=valgrind-%p.xml --suppressions=${SUPPRESSIONS_FILE}")
else ()
    message(WARNING "Valgrind not found")
endif ()
