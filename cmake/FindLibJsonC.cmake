##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

find_path(LIBJSONC_INCLUDE_DIR json-c/json.h)
find_library(LIBJSONC_LIBRARY NAMES libjson-c.so)
mark_as_advanced(LIBJSONC_INCLUDE_DIR LIBJSONC_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LibJsonC
    DEFAULT_MSG
    LIBJSONC_INCLUDE_DIR LIBJSONC_LIBRARY
)

if(LibJsonC_FOUND)
    set(LIBJSONC_LIBRARIES ${LIBJSONC_LIBRARY})
    set(LIBJSONC_INCLUDE_DIRS ${LIBJSONC_INCLUDE_DIR})
    if(NOT TARGET LibJsonC::LibJsonC)
        add_library(LibJsonC::LibJsonC SHARED IMPORTED)
        set_target_properties(LibJsonC::LibJsonC
            PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${LIBJSONC_INCLUDE_DIR}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${LIBJSONC_LIBRARY}"
            IMPORTED_NO_SONAME 1
        )
    endif()
endif()

message(STATUS "libjsonc include dir: ${LIBJSONC_INCLUDE_DIRS}")
message(STATUS "libjsonc: ${LIBJSONC_LIBRARIES}")

