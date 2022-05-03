##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

project(utils
    DESCRIPTION "Easy-mesh controller"
    LANGUAGES C
)

set(UTILS utils)
set(UTILSSTATIC utils-static)

set(UTILS_SOURCES
    arraylist.c
    kwaytree.c
    map_80211.c
    map_airdata.c
    map_cli.c
    map_cli_subscription.c
    map_config.c
    map_data_model.c
    map_data_model_dumper.c
    map_dm_airdata.c
    map_info.c
    map_retry_handler.c
    map_timer_handler.c
    map_topology_tree.c
    map_utils.c
    map_zlib.c
)

foreach(src_file ${UTILS_SOURCES})
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/src/${src_file})
endforeach()

set(UTILS_INCLUDES
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PUBLIC ${LIBUBOX_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/source/ssp
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/ccsp/custom
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/ccsp/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/ccsp/components/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/cosa/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/cosa/include/linux
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/cosa/package/slap/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/debug_api/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/util_api/ansc/include
    /opt/home/airties/rpi3b/rdkb/components/opensource/ccsp/CcspCommonLibrary/source/util_api/http/include
    /opt/home/airties/rpi3b/build-raspberrypi-rdk-broadband/tmp/work/cortexa7t2hf-neon-vfpv4-rdk-linux-gnueabi/dbus/1.12.16-r0/dbus-1.12.16
    /opt/home/airties/rpi3b/build-raspberrypi-rdk-broadband/tmp/work/cortexa7t2hf-neon-vfpv4-rdk-linux-gnueabi/dbus/1.12.16-r0/sysroot-destdir/usr/lib/dbus-1.0/include
)

set(UTILS_COMPILE_OPTIONS
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

set(UTILS_LIBRARIES
    ${ZLIB_LIBRARIES}
    LibUbox::LibUbox
    LibJsonC::LibJsonC
    -Wl,--gc-sections
# uncomment if you want to see which symbols are GC'd
#    -Wl,--print-gc-sections
)

# Library objects
add_library(${UTILS}-objs OBJECT ${SOURCES})
target_compile_definitions(${UTILS}-objs PRIVATE
    _GNU_SOURCE
)
target_compile_options(${UTILS}-objs PRIVATE ${UTILS_COMPILE_OPTIONS})
target_include_directories(${UTILS}-objs ${UTILS_INCLUDES})

# Dynamic library
#add_library(${UTILS} SHARED $<TARGET_OBJECTS:${UTILS}-objs>)
#target_link_libraries(${UTILS} ${UTILS_LIBRARIES})

# Static library
add_library(${UTILSSTATIC} STATIC $<TARGET_OBJECTS:${UTILS}-objs>)
set_target_properties(${UTILSSTATIC} PROPERTIES OUTPUT_NAME ${UTILS})
target_link_libraries(${UTILSSTATIC} ${UTILS_LIBRARIES})

# Install header file(s)
#install(
#    DIRECTORY ${PROJECT_SOURCE_DIR}/include
#    DESTINATION include
#)

# Install library
#install(TARGETS ${LIBSTATIC}
#    RUNTIME DESTINATION bin
#    LIBRARY DESTINATION lib
#    ARCHIVE DESTINATION lib
#)
