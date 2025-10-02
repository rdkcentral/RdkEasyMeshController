#!/bin/sh

##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

mkdir -p ./project/build
cd project/build && cmake .. && make VERBOSE=1 && cd ..
