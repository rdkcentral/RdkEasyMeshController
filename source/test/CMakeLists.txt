##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

cmake_minimum_required(VERSION 2.8.12)

project(multiap-controller_test)

set(SCHEMA_PATH "dummy" CACHE STRING "JSON schema path")

set(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(CHECK REQUIRED)
find_package(LIBUBOX REQUIRED)
find_package(JSONC REQUIRED)

add_definitions(-O0 -Wall -Werror -D_GNU_SOURCE -DUNIT_TEST)

if(OPENSSL_VERSION VERSION_GREATER "3.0.0")
  add_definitions(-Wno-deprecated-declarations)
endif()

find_program(JSONSCHEMA_TOOL jsonschema)
if(JSONSCHEMA_TOOL)
  add_definitions(-DJSONSCHEMA_TOOL=\"${JSONSCHEMA_TOOL}\")
endif()


# Module paths
set(CONTROLLER_DIR         ${CMAKE_SOURCE_DIR}/../controller)
set(CONTROLLER_SRC_DIR     ${CONTROLLER_DIR}/src)
set(CONTROLLER_INCLUDE_DIR ${CONTROLLER_DIR}/include)
set(LIBUTILS_DIR           ${CMAKE_SOURCE_DIR}/../libplatform)
set(LIBUTILS_SRC_DIR       ${LIBUTILS_DIR}/src)
set(LIBUTILS_INCLUDE_DIR   ${LIBUTILS_DIR}/include)
set(IEEE1905_DIR           ${CMAKE_SOURCE_DIR}/../ieee1905)
set(IEEE1905_SRC_DIR       ${IEEE1905_DIR}/src)
set(IEEE1905_INCLUDE_DIRS
    ${IEEE1905_SRC_DIR}/al/internal_interfaces
    ${IEEE1905_SRC_DIR}/al/src_independent
    ${IEEE1905_DIR}/src/al/src_independent/extensions/map/
    ${IEEE1905_DIR}/src/common/interfaces
    ${IEEE1905_DIR}/src/factory/interfaces
    ${IEEE1905_DIR}/src/factory/interfaces/extensions/map
)


# ieee1905 factory sources
set(IEEE1905_FACTORY_SRCS
    ${IEEE1905_SRC_DIR}/factory/src_independent/1905_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/lldp_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/extensions/map/map_r1_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/extensions/map/map_r2_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/extensions/map/map_r3_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/extensions/map/map_r4_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/extensions/map/map_r6_tlvs.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/1905_cmdus.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/lldp_payload.c
    ${IEEE1905_SRC_DIR}/factory/src_independent/media_specific_blobs.c
)


# Common include dirs
set(UNIT_TEST_INCLUDES
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_SOURCE_DIR}/common/stub
    ${LIBUTILS_INCLUDE_DIR}
    ${IEEE1905_INCLUDE_DIRS}
    ${CONTROLLER_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LIBUBOX_INCLUDE_DIRS}
    ${JSONC_INCLUDE_DIRS}
    ${CHECK_INCLUDE_DIRS}
)


# Common libraries
set(UNIT_TEST_LIBS
    unit_test
    ${CHECK_LIBRARIES}
    ${LIBUBOX_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${JSONC_LIBRARIES}
    pcap
    pthread rt m
)


# Tests
include(ValgrindSupport) # needs to configured before CTest include
include(CTest) # needs to be in top-level CMakeLists.txt


# Support for coverage reporting
include(CodeCoverage)
setup_target_for_coverage(test_coverage "${CMAKE_CTEST_COMMAND}" coverage_report "-VV;-R;unittest")
setup_target_for_coverage_cobertura(test_coverage_cobertura "${CMAKE_CTEST_COMMAND}" cobertura_report "-VV;-R;unittest")
setup_target_for_coverage_cobertura(test_coverage_cobertura_collect_only "" cobertura_report)


# Actual tests
enable_testing()
add_subdirectory(common)
add_subdirectory(libutils)
add_subdirectory(ieee1905)
add_subdirectory(controller)
