##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

#
# Find jsonc-c
#
#  JSONC_INCLUDE_DIRS - where to find json-c/json.h, etc.
#  JSONC_LIBRARIES    - List of libraries when using json-c
#  JSONC_FOUND        - True if json-c found.

if (NOT JSONC_INCLUDE_DIR)
  find_path(JSONC_INCLUDE_DIR json-c/json.h)
endif()

if (NOT JSONC_LIBRARY)
  find_library(
    JSONC_LIBRARY
    NAMES libjson-c.so)
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  JSONC DEFAULT_MSG
  JSONC_LIBRARY JSONC_INCLUDE_DIR)

if(JSONC_FOUND)
    set(JSONC_LIBRARIES ${JSONC_LIBRARY})
    set(JSONC_INCLUDE_DIRS ${JSONC_INCLUDE_DIR})
else(JSONC_FOUND)
    set(JSONC_LIBRARIES)
    set(JSONC_INCLUDE_DIRS)
endif(JSONC_FOUND)

message(STATUS "json-c include dir: ${JSONC_INCLUDE_DIRS}")
message(STATUS "json-c: ${JSONC_LIBRARIES}")

mark_as_advanced(JSONC_INCLUDE_DIRS JSONC_LIBRARIES)
