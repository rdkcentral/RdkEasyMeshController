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

lib_LIBRARIES = libcommon.a

libcommon_a_CPPFLAGS = -I$(srcdir)/interfaces \
                       -I$(top_srcdir)/source/libplatform/include

libcommon_a_SOURCES = $(srcdir)/src_independent/utils.c \
                      $(srcdir)/src_linux/platform.c

