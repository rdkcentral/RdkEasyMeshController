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

add_definitions("-DMULTIAP")
add_definitions("-D_FLAVOUR_AIRTIES_")
add_definitions("-DSEND_EMPTY_TLVS")
add_definitions("-DFIX_BROKEN_TLVS")
add_definitions("-DSPEED_UP_DISCOVERY")

add_subdirectory(src/common)
add_subdirectory(src/factory)
add_subdirectory(src/al)
