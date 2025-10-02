Unit Tests
==========

# Introduction

This tool attempts to verify the functionality of various parts of the EasyMesh controller. For this purpose, the "check" library is used, which is a unit test framework for C projects. The tool is designed to run on PC, so it is not cross-compiled for the target.

# Prerequisites
In order to compile and run the tool the following packages must be installed, as well as the basic development tools like gcc, make and cmake.

- check (Unit Testing Framework for C)
- valgrind (Instrumentation Framework for Building Dynamic Analysis Tools)
- gcov (a Test Coverage Program)

# Structure
Unit test tool has the following folders.

- cmake, contains files with directives needed for different packages cmake uses
- common, contains common code used by main controller modules
- libplatform, contains unit tests for libplatform module
- ieee1905, contains unit tests for ieee1905 module
- controller, contains unit tests for controller module
- project, contains external source packets and all build data

All controller modules contain data and stub folders and their respective unit test codes focusing on that modules functionalities. "data" folder contains necessary data for unit tests to operate. Most of them are generated from actual network captures. "stub" folder contains code that take the place of the actual code which is not in the focus of the unit tests.

# Usage
There are 2 shell scripts in the root folder to ease the usage of the tool.

The shell script "setup.sh" will download and compile all necessary external sources (cJSON, json-c, libubox, uthash) needed for the unit test tool. After external sources are ready unit tests will be compiled. After successful build, the tool will be ready to use.

"run.sh" is used to conduct unit tests. It is possible to run a specific tests as well as all tests at once. Tool also provides code coverage and memory analysis options while performing unit tests.

# Tests

Every item in the following list have their own unit tests covering that topic.

## libplatform
- arraylist
- map_80211
- map_blocklist
- map_channel_set
- map_cli_subscription
- map_datamodel
- map_dm_eth_device_list
- map_info

## ieee1905
- al_send
- al_wsc
- cmdus
- lldp_payload
- lldp_tlvs
- tlvs

## controller
- chan_sel
- cli
- cmdu_rx
- cmdu_tx
- emex
- tlv_helper
- utils
