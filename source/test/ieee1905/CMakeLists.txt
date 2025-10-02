##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

set(SRC_DIR ${IEEE1905_SRC_DIR})

include(../common/CheckUnitTest.cmake)

set(AL_SRCS
    ${SRC_DIR}/al/src_independent/al_entity.c
    ${SRC_DIR}/al/src_independent/al_datamodel.c
    ${SRC_DIR}/al/src_independent/al_recv.c
    ${SRC_DIR}/al/src_independent/al_send.c
    ${SRC_DIR}/al/src_independent/al_wsc.c
    ${SRC_DIR}/al/src_independent/al_utils.c
    ${SRC_DIR}/al/src_linux/platform_interfaces.c
    ${SRC_DIR}/al/src_linux/platform_crypto.c
)

set(COMMON_SRCS
    ${SRC_DIR}/common/src_independent/utils.c
    ${SRC_DIR}/common/src_linux/platform.c
)

set(UNIT_TEST_EXTRA_DEFINES
    _FLAVOUR_AIRTIES_
    MULTIAP
)

SETUP_UNIT_TEST(tlvs
    ${COMMON_SRCS}
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(cmdus
    ${AL_SRCS}
    ${COMMON_SRCS}
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(lldp_tlvs
    ${SRC_DIR}/factory/src_independent/lldp_tlvs.c
    ${COMMON_SRCS}
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(lldp_payload
    ${SRC_DIR}/factory/src_independent/lldp_payload.c
    ${SRC_DIR}/factory/src_independent/lldp_tlvs.c
    ${COMMON_SRCS}
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(al_wsc
    ${AL_SRCS}
    ${COMMON_SRCS}
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)

SETUP_UNIT_TEST(al_send
    ${AL_SRCS}
    ${COMMON_SRCS}
    ${IEEE1905_FACTORY_SRCS}
    ${LIBUTILS_SRC_DIR}/acu_utils.c
)
