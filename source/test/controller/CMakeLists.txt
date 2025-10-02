##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

set(SRC_DIR ${CONTROLLER_SRC_DIR})

include(../common/CheckUnitTest.cmake)

SETUP_UNIT_TEST(cmdu_rx
    ${SRC_DIR}/map_ctrl_cmdu_rx.c
    ${SRC_DIR}/map_ctrl_cmdu_validator.c
    ${SRC_DIR}/map_ctrl_cmdu_handler.c
    ${SRC_DIR}/map_ctrl_tlv_parser.c
    ${SRC_DIR}/map_ctrl_sta.c
    ${SRC_DIR}/map_ctrl_metrics_handler.c
    ${SRC_DIR}/map_ctrl_onboarding_handler.c
    ${SRC_DIR}/map_ctrl_post_onboarding_handler.c
    ${SRC_DIR}/map_ctrl_emex_tlv_handler.c
    ${SRC_DIR}/map_ctrl_utils.c
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/map_data_model_dumper.c
    ${LIBUTILS_SRC_DIR}/map_topology_tree.c
    ${LIBUTILS_SRC_DIR}/kwaytree.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/map_80211.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/map_info.c
    ${LIBUTILS_SRC_DIR}/map_staging_list.c
    ${LIBUTILS_SRC_DIR}/map_blocklist.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(cmdu_tx
    ${SRC_DIR}/map_ctrl_cmdu_tx.c
    ${SRC_DIR}/map_ctrl_cmdu_rx.c
    ${SRC_DIR}/map_ctrl_cmdu_validator.c
    ${SRC_DIR}/map_ctrl_cmdu_handler.c
    ${SRC_DIR}/map_ctrl_tlv_parser.c
    ${SRC_DIR}/map_ctrl_metrics_handler.c
    ${SRC_DIR}/map_ctrl_onboarding_handler.c
    ${SRC_DIR}/map_ctrl_post_onboarding_handler.c
    ${SRC_DIR}/map_ctrl_tlv_helper.c
    ${SRC_DIR}/map_ctrl_utils.c
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/map_topology_tree.c
    ${LIBUTILS_SRC_DIR}/kwaytree.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/map_80211.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/map_info.c
    ${LIBUTILS_SRC_DIR}/map_staging_list.c
    ${LIBUTILS_SRC_DIR}/map_blocklist.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(emex
    ${SRC_DIR}/map_ctrl_emex_tlv_handler.c
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(utils
    ${SRC_DIR}/map_ctrl_utils.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/map_info.c
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/map_80211.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(tlv_helper
    ${SRC_DIR}/map_ctrl_tlv_helper.c
    ${SRC_DIR}/map_ctrl_utils.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/map_info.c
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/map_80211.c
    ${LIBUTILS_SRC_DIR}/kwaytree.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
    ${IEEE1905_FACTORY_SRCS}
)

SETUP_UNIT_TEST(cli
    ${SRC_DIR}/map_ctrl_cli.c
    ${LIBUTILS_SRC_DIR}/map_cli_subscription.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/map_info.c
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/map_data_model_dumper.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/kwaytree.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
    ${IEEE1905_FACTORY_SRCS}
)

SETUP_UNIT_TEST(chan_sel
    ${SRC_DIR}/map_ctrl_chan_sel.c
    ${SRC_DIR}/map_ctrl_utils.c
    ${LIBUTILS_SRC_DIR}/map_data_model.c
    ${LIBUTILS_SRC_DIR}/arraylist.c
    ${LIBUTILS_SRC_DIR}/kwaytree.c
    ${LIBUTILS_SRC_DIR}/map_channel_set.c
    ${LIBUTILS_SRC_DIR}/map_info.c
    ${LIBUTILS_SRC_DIR}/map_80211.c
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)
