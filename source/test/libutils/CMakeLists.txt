##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

set(SRC_DIR ${LIBUTILS_SRC_DIR})

include(../common/CheckUnitTest.cmake)

SETUP_UNIT_TEST(map_datamodel
    ${SRC_DIR}/map_data_model.c
    ${SRC_DIR}/map_data_model_dumper.c
    ${SRC_DIR}/map_channel_set.c
    ${SRC_DIR}/map_info.c
    ${SRC_DIR}/arraylist.c
    ${SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(map_dm_eth_device_list
    ${SRC_DIR}/map_dm_eth_device_list.c
    ${SRC_DIR}/map_data_model.c
    ${SRC_DIR}/arraylist.c
    ${SRC_DIR}/kwaytree.c
    ${SRC_DIR}/map_channel_set.c
    ${SRC_DIR}/map_info.c
    ${SRC_DIR}/map_topology_tree.c
    ${SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(map_info
    ${SRC_DIR}/map_info.c
    ${SRC_DIR}/map_channel_set.c
)

SETUP_UNIT_TEST(map_channel_set
    ${SRC_DIR}/map_channel_set.c
)

SETUP_UNIT_TEST(map_80211
    ${SRC_DIR}/map_80211.c
    ${SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(map_cli_subscription
    ${SRC_DIR}/map_cli_subscription.c
)

SETUP_UNIT_TEST(map_blocklist
    ${SRC_DIR}/map_blocklist.c
    ${SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(arraylist
    ${SRC_DIR}/arraylist.c
)
