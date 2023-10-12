##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CFLAGS += -D_GNU_SOURCE
AM_CFLAGS += -Wall -Wextra -Werror

AM_CFLAGS += -DFEATURE_SUPPORT_RDKLOG

lib_LIBRARIES = libcontroller.a

libcontroller_a_CPPFLAGS = -I$(top_srcdir)/source/controller/include \
                           -I$(top_srcdir)/source/libplatform/include \
                           -I$(top_srcdir)/source/ieee1905/src/common/interfaces \
                           -I$(top_srcdir)/source/ieee1905/src/factory/interfaces \
                           -I$(top_srcdir)/source/ieee1905/src/factory/interfaces/extensions/map \
                           -I$(top_srcdir)/source/ieee1905/src/al/src_independent/extensions/map

libcontroller_a_SOURCES = map_ctrl_chan_sel.c \
                          map_ctrl_cli.c \
                          map_ctrl_cmdu_handler.c \
                          map_ctrl_cmdu_rx.c \
                          map_ctrl_cmdu_tx.c \
                          map_ctrl_cmdu_validator.c \
                          map_ctrl_config.c \
                          map_ctrl_emex_tlv_handler.c \
                          map_ctrl_main.c \
                          map_ctrl_metrics_handler.c \
                          map_ctrl_nbapi.c \
                          map_ctrl_onboarding_handler.c \
                          map_ctrl_post_onboarding_handler.c \
                          map_ctrl_tlv_helper.c \
                          map_ctrl_tlv_parser.c \
                          map_ctrl_topology_tree.c \
                          map_ctrl_utils.c \
                          map_ctrl_wfa_capi.c

