##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

#
# Find libubox
#
#  LIBUBOX_INCLUDE_DIRS - where to find libubox/uloop.h, etc.
#  LIBUBOX_LIBRARIES    - List of libraries when using libubox
#  LIBUBOX_FOUND        - True if libubox found.

if (NOT LIBUBOX_INCLUDE_DIR)
  find_path(LIBUBOX_INCLUDE_DIR libubox/uloop.h)
endif()

if (NOT LIBUBOX_LIBRARY)
  find_library(
    LIBUBOX_LIBRARY
    NAMES libubox.so)
endif()

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(
  LIBUBOX DEFAULT_MSG
  LIBUBOX_LIBRARY LIBUBOX_INCLUDE_DIR)

if(LIBUBOX_FOUND)
    set(LIBUBOX_LIBRARIES ${LIBUBOX_LIBRARY})
    set(LIBUBOX_INCLUDE_DIRS ${LIBUBOX_INCLUDE_DIR})
else(LIBUBOX_FOUND)
    set(LIBUBOX_LIBRARIES)
    set(LIBUBOX_INCLUDE_DIRS)
endif(LIBUBOX_FOUND)

message(STATUS "libubox include dir: ${LIBUBOX_INCLUDE_DIRS}")
message(STATUS "libubox: ${LIBUBOX_LIBRARIES}")

mark_as_advanced(LIBUBOX_INCLUDE_DIRS LIBUBOX_LIBRARIES)
