##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

project(ieee1905
    DESCRIPTION "ieee1905"
    LANGUAGES C
)

set(COMMON_INCLUDES
    PRIVATE ${PROJECT_SOURCE_DIR}/src/common/interfaces
)

set(FACTORY_INCLUDES
    PRIVATE ${PROJECT_SOURCE_DIR}/src/factory/interfaces
    PRIVATE ${PROJECT_SOURCE_DIR}/src/factory/interfaces/extensions/map
)

set(SYSTEM_INCLUDES
    PRIVATE ${CMAKE_SOURCE_DIR}/source/libplatform/include
    ${CMAKE_SOURCE_DIR}/source/ssp
    PUBLIC ${LIBUBOX_INCLUDE_DIRS}
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/ccsp
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/dbus-1.0
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/lib/dbus-1.0/include
)

add_compile_options(
    -Wall
    -Wextra
    -Werror
    -fPIC
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

add_definitions("-DMULTIAP")
add_definitions("-D_FLAVOUR_AIRTIES_")
add_definitions("-DSEND_EMPTY_TLVS")
add_definitions("-DFIX_BROKEN_TLVS")
add_definitions("-DSPEED_UP_DISCOVERY")

add_subdirectory(src/common)
add_subdirectory(src/factory)
add_subdirectory(src/al)
