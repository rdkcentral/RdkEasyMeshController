##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

cmake_minimum_required(VERSION 3.10)

project(em-ctl
    DESCRIPTION "EasyMesh Controller"
    LANGUAGES C
)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(LibUbox REQUIRED)
find_package(LibJsonC REQUIRED)

add_compile_definitions(_GNU_SOURCE)

add_subdirectory(source)
