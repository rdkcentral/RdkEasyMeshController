##########################################################################
# Copyright (c) 2021-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

include(CheckUnitTest.cmake)

# Shared library including all stubs.
# Linker will only use them if the real source file is not included
# in a test.

set(STUB_COMMON
    stub_acutils.c
)
list(TRANSFORM STUB_COMMON PREPEND ../common/stub/)

set(STUB_LIBUTILS
    stub_map_cli.c
    stub_map_data_model.c
    stub_map_dm_rbus.c
    stub_map_retry_handler.c
    stub_map_topology_tree.c
    stub_map_blocklist.c
    stub_map_config.c
    stub_map_dm_eth_device_list.c
    stub_map_timer_handler.c
    stub_map_utils.c
)
list(TRANSFORM STUB_LIBUTILS PREPEND ../libutils/stub/)

set(STUB_IEEE1905
    stub_i1905.c
    stub_platform_os.c
)
list(TRANSFORM STUB_IEEE1905 PREPEND ../ieee1905/stub/)

set(STUB_CONTROLLER
    stub_map_ctrl_emex_tlv_handler.c
    stub_map_ctrl_post_onboarding_handler.c
    stub_map_ctrl_utils.c
    stub_map_ctrl_chan_sel.c
    stub_map_ctrl_tlv_helper.c
    stub_map_ctrl_vendor.c
    stub_map_ctrl_cmdu_tx.c
    stub_map_ctrl_topology_tree.c
    stub_map_ctrl_wfa_capi.c
)
list(TRANSFORM STUB_CONTROLLER PREPEND ../controller/stub/)

SETUP_UNIT_TEST_LIB(
    main.c
    utils.c

    ${STUB_COMMON}
    ${STUB_LIBUTILS}
    ${STUB_IEEE1905}
    ${STUB_CONTROLLER}
)
