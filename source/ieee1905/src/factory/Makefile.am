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

lib_LIBRARIES = libfactory.a

libfactory_a_CPPFLAGS = -I$(srcdir)/interfaces \
                        -I$(srcdir)/interfaces/extensions/map \
                        -I$(top_srcdir)/source/libplatform/include \
                        -I$(top_srcdir)/source/ieee1905/src/common/interfaces

libfactory_a_SOURCES = $(srcdir)/src_independent/1905_cmdus.c \
                       $(srcdir)/src_independent/1905_tlvs.c \
                       $(srcdir)/src_independent/lldp_payload.c \
                       $(srcdir)/src_independent/lldp_tlvs.c \
                       $(srcdir)/src_independent/media_specific_blobs.c \
                       $(srcdir)/src_independent/extensions/map/map_r1_tlvs.c \
                       $(srcdir)/src_independent/extensions/map/map_r2_tlvs.c \
                       $(srcdir)/src_independent/extensions/map/map_r3_tlvs.c

