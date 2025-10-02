##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

cmake_minimum_required(VERSION 2.8.12)

project(emctl_test_project)

option(BUILD_DEPS "Build dependencies" OFF)
set(CJSON_SRC_URL "https://github.com/DaveGamble/cJSON.git" CACHE STRING "Default cJSON repository")
set(CJSON_REVISION "v1.7.12" CACHE STRING "Default cJSON revision")
set(JSONC_SRC_URL "https://github.com/json-c/json-c.git" CACHE STRING "Default json-c repository")
set(JSONC_REVISION "json-c-0.15-20200726" CACHE STRING "Default json-c revision")
set(LIBUBOX_SRC_URL "https://github.com/openwrt/libubox.git" CACHE STRING "Default libubox repository")
set(LIBUBOX_REVISION "e85cb739766d00977a08cce98f161976da5fbefc" CACHE STRING "Default libubox revision")
set(UTHASH_SRC_URL "https://github.com/troydhanson/uthash.git" CACHE STRING "Default uthash repository")
set(UTHASH_REVISION "v2.3.0" CACHE STRING "Default uthash revision")

include(ExternalProject)

set(INSTALL_DIR ${PROJECT_BINARY_DIR}/install)

ExternalProject_Add(
  cJSON
  PREFIX cJSON
  DOWNLOAD_COMMAND git clone ${CJSON_SRC_URL} cJSON && git -C cJSON checkout ${CJSON_REVISION}
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
    -DENABLE_CJSON_TEST=OFF
  BUILD_COMMAND make
)

ExternalProject_Add(
  json-c
  PREFIX json-c
  DOWNLOAD_COMMAND git clone ${JSONC_SRC_URL} json-c && git -C json-c checkout ${JSONC_REVISION}
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
)

ExternalProject_Add(
  libubox
  PREFIX libubox
  DEPENDS json-c
  DOWNLOAD_COMMAND git clone ${LIBUBOX_SRC_URL} libubox && git -C libubox checkout ${LIBUBOX_REVISION}
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
    -DJSONC_FOUND=1
    -DJSONC_INCLUDE_DIRS=${INSTALL_DIR}/include/json-c
    -DBUILD_LUA=OFF
    -DBUILD_EXAMPLES=OFF
    -DUNIT_TESTING=OFF
  BUILD_COMMAND make
)

ExternalProject_Add(
  uthash
  PREFIX uthash
  DOWNLOAD_COMMAND git clone ${UTHASH_SRC_URL} uthash && git -C uthash checkout ${UTHASH_REVISION}
  CONFIGURE_COMMAND ""
  BUILD_IN_SOURCE TRUE
  BUILD_COMMAND ln -sf include uthash
  INSTALL_COMMAND mkdir -p ${INSTALL_DIR}/include && cp -rfH uthash ${INSTALL_DIR}/include
)

set(TESTS_DEPENDS libubox cJSON json-c)

ExternalProject_Add(
  tests
  PREFIX tests
  DEPENDS ${TESTS_DEPENDS}
  SOURCE_DIR ${PROJECT_SOURCE_DIR}/..
  CMAKE_ARGS
    -DCMAKE_FIND_ROOT_PATH=${INSTALL_DIR} -DSCHEMA_PATH=${INSTALL_DIR}/schemas
  BUILD_COMMAND make VERBOSE=1
  INSTALL_COMMAND ""
)
