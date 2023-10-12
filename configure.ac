##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

dnl AC_PREREQ([2.69])
AC_INIT(EasyMeshController-rdkb, version-1.0)
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-bzip2 1.9 subdir-objects])
LT_INIT

dnl subdirectories.
SUBDIRS=""

dnl Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CPP
AC_PROG_CXXCPP

dnl use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])




dnl **********************************
dnl checks for dependencies
dnl **********************************
AC_HEADER_STDC

dnl Checks for header files.
AC_CHECK_HEADERS([limits.h memory.h stdlib.h string.h sys/socket.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
dnl AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT8_T

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strerror asprintf])

PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.0.1f])
PKG_CHECK_MODULES([JSONC], [json-c >= 0.12])
PKG_CHECK_MODULES([DBUS], [dbus-1 >= 1.6.18])

AC_CONFIG_FILES([Makefile
		source/Makefile
		source/libplatform/Makefile
		source/libplatform/src/Makefile
		source/ieee1905/Makefile
		source/ieee1905/src/common/Makefile
		source/ieee1905/src/factory/Makefile
		source/ieee1905/src/al/Makefile
		source/ssp/Makefile
		source/controller/Makefile
		source/controller/src/Makefile
		source/tools/Makefile
		source/tools/map_cli/Makefile])
AC_OUTPUT
