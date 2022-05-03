##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -Werror -D_GNU_SOURCE
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = em_ctl
em_ctl_CPPFLAGS = -I$(top_srcdir)/source/controller/include \
                  -I$(top_srcdir)/source/libplatform/include \
                  -I$(top_srcdir)/source/ieee1905/src/common/interfaces \
                  -I$(top_srcdir)/source/ieee1905/src/factory/interfaces \
                  -I$(top_srcdir)/source/ieee1905/src/factory/interfaces/extensions/map \
                  -I$(top_srcdir)/source/ieee1905/src/al/src_independent/extensions/map \
                  -I$(top_srcdir)/source/ssp

em_ctl_SOURCES = $(srcdir)/map_ctrl_cli.c \
                 $(srcdir)/map_ctrl_cmdu_handler.c \
                 $(srcdir)/map_ctrl_cmdu_rx.c \
                 $(srcdir)/map_ctrl_cmdu_tx.c \
                 $(srcdir)/map_ctrl_cmdu_validator.c \
                 $(srcdir)/map_ctrl_compress.c \
                 $(srcdir)/map_ctrl_config.c \
                 $(srcdir)/map_ctrl_main.c \
                 $(srcdir)/map_ctrl_metrics_handler.c \
                 $(srcdir)/map_ctrl_onboarding_handler.c \
                 $(srcdir)/map_ctrl_post_onboarding_handler.c \
                 $(srcdir)/map_ctrl_tlv_helper.c \
                 $(srcdir)/map_ctrl_tlv_parser.c \
                 $(srcdir)/map_ctrl_topology_tree.c \
                 $(srcdir)/map_ctrl_utils.c \
                 $(srcdir)/map_ctrl_wfa_capi.c

em_ctl_LDADD = ${top_builddir}/source/libplatform/src/libutils.a \
               ${top_builddir}/source/ieee1905/src/al/libal.a \
               ${top_builddir}/source/ieee1905/src/factory/libfactory.a \
               ${top_builddir}/source/ieee1905/src/common/libcommon.a \               
               ${top_builddir}/source/ssp/libssp.a


em_ctl_CPPFLAGS += $(SYSTEMD_CFLAGS) 
em_ctl_CPPFLAGS += "-DFEATURE_SUPPORT_RDKLOG"
em_ctl_LDFLAGS = -lccsp_common -ldl -rdynamic $(SYSTEMD_LDFLAGS) -llog4c


