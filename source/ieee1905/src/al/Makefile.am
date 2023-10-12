##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CFLAGS += -D_GNU_SOURCE
AM_CFLAGS += -Wall -Wextra -Werror

AM_CFLAGS += -DMULTIAP -D_FLAVOUR_AIRTIES_ -DSEND_EMPTY_TLVS -DFIX_BROKEN_TLVS -DSPEED_UP_DISCOVERY

lib_LIBRARIES = libal.a

libal_a_CPPFLAGS = -I$(srcdir)/internal_interfaces \
                   -I$(srcdir)/src_independent \
                   -I$(srcdir)/src_independent/extensions/map \
                   -I$(top_srcdir)/source/libplatform/include \
                   -I$(top_srcdir)/source/ieee1905/src/common/interfaces \
                   -I$(top_srcdir)/source/ieee1905/src/factory/interfaces \
                   -I$(top_srcdir)/source/ieee1905/src/factory/interfaces/extensions/map

libal_a_SOURCES = $(srcdir)/src_independent/al_recv.c \
                  $(srcdir)/src_independent/al_send.c \
                  $(srcdir)/src_independent/al_utils.c \
                  $(srcdir)/src_independent/al_wsc.c \
                  $(srcdir)/src_independent/al_datamodel.c \
                  $(srcdir)/src_independent/al_entity.c \
                  $(srcdir)/src_independent/extensions/map/i1905.c \
                  $(srcdir)/src_linux/platform_crypto.c \
                  $(srcdir)/src_linux/platform_interfaces.c \
                  $(srcdir)/src_linux/platform_os.c

