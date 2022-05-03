##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

find_path(LIBUBOX_INCLUDE_DIR libubox/uloop.h)
find_library(LIBUBOX_LIBRARY NAMES libubox.so)
mark_as_advanced(LIBUBOX_INCLUDE_DIR LIBUBOX_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LibUbox
    DEFAULT_MSG
    LIBUBOX_INCLUDE_DIR LIBUBOX_LIBRARY
)

if(LibUbox_FOUND)
    set(LIBUBOX_LIBRARIES ${LIBUBOX_LIBRARY})
    set(LIBUBOX_INCLUDE_DIRS ${LIBUBOX_INCLUDE_DIR})
    if(NOT TARGET LibUbox::LibUbox)
        add_library(LibUbox::LibUbox SHARED IMPORTED)
        set_target_properties(LibUbox::LibUbox
            PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${LIBUBOX_INCLUDE_DIR}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${LIBUBOX_LIBRARY}"
        )
    endif()
endif()

message(STATUS "libubox include dir: ${LIBUBOX_INCLUDE_DIRS}")
message(STATUS "libubox: ${LIBUBOX_LIBRARIES}")

