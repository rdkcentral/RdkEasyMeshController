##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

project(utils
    DESCRIPTION "Utils and Platform component"
    LANGUAGES C
)

set(UTILS utils)
set(UTILSSTATIC utils-static)

set(UTILS_SOURCES
    acu_utils.c
    arraylist.c
    kwaytree.c
    map_80211.c
    map_blocklist.c
    map_channel_set.c
    map_cli.c
    map_cli_subscription.c
    map_config.c
    map_data_model.c
    map_data_model_dumper.c
    map_dm_eth_device_list.c
    map_dm_rbus.c
    map_info.c
    map_retry_handler.c
    map_staging_list.c
    map_timer_handler.c
    map_topology_tree.c
    map_utils.c
)

foreach(src_file ${UTILS_SOURCES})
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/src/${src_file})
endforeach()

set(UTILS_INCLUDES
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PUBLIC ${LIBUBOX_INCLUDE_DIRS}
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/ccsp
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/dbus-1.0
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/lib/dbus-1.0/include
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/rbus
)

set(UTILS_COMPILE_OPTIONS
    -Wall
    -Wextra
    -Werror
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

set(UTILS_LIBRARIES
    ${ZLIB_LIBRARIES}
    LibUbox::LibUbox
    LibJsonC::LibJsonC
    -lrbus
    -Wl,--gc-sections
)

# Library objects
add_library(${UTILS}-objs OBJECT ${SOURCES})
target_compile_options(${UTILS}-objs PRIVATE ${UTILS_COMPILE_OPTIONS})
target_include_directories(${UTILS}-objs ${UTILS_INCLUDES})

# Static library
add_library(${UTILSSTATIC} STATIC $<TARGET_OBJECTS:${UTILS}-objs>)
set_target_properties(${UTILSSTATIC} PROPERTIES OUTPUT_NAME ${UTILS})
target_link_libraries(${UTILSSTATIC} ${UTILS_LIBRARIES})

