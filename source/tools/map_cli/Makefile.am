##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CFLAGS += -D_GNU_SOURCE
AM_CFLAGS += -Wall -Wextra -Werror

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = map_cli
map_cli_CFLAGS = -I$(top_srcdir)/source/libplatform/include

map_cli_SOURCES = map_cli.c

map_cli_LDADD = ${top_builddir}/source/libplatform/src/libutils.a
