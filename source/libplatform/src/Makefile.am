##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

AM_CPPFLAGS = -D_GNU_SOURCE -DFEATURE_SUPPORT_RDKLOG -D_ANSC_LINUX -D_ANSC_USER

lib_LIBRARIES = libutils.a

libutils_a_CFLAGS = -I$(top_srcdir)/source/libplatform/include -I$(top_srcdir)/source/ssp -I$(TOPDIR)/usr/include/libubox -I${JSONC_INC_DIR}

libutils_a_SOURCES = arraylist.c \
                     kwaytree.c \
                     map_80211.c \
                     map_airdata.c \
                     map_cli.c \
                     map_cli_subscription.c \
                     map_config.c \
                     map_data_model.c \
                     map_data_model_dumper.c \
                     map_dm_airdata.c \
                     map_info.c \
                     map_retry_handler.c \
                     map_timer_handler.c \
                     map_topology_tree.c \
                     map_utils.c \
                     map_zlib.c

libutils_a_LDFLAGS = -lz -ljson-c -lubox -lccsp_common -llog4c
