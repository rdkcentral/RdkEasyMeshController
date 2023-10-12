##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

# name of the executable
set(EXE em-ctl)

set(EXE_SOURCES
    map_ctrl_chan_sel.c
    map_ctrl_cli.c
    map_ctrl_cmdu_handler.c
    map_ctrl_cmdu_rx.c
    map_ctrl_cmdu_tx.c
    map_ctrl_cmdu_validator.c
    map_ctrl_config.c
    map_ctrl_emex_tlv_handler.c
    map_ctrl_main.c
    map_ctrl_metrics_handler.c
    map_ctrl_nbapi.c
    map_ctrl_onboarding_handler.c
    map_ctrl_post_onboarding_handler.c
    map_ctrl_tlv_helper.c
    map_ctrl_tlv_parser.c
    map_ctrl_topology_tree.c
    map_ctrl_utils.c
    map_ctrl_wfa_capi.c
)

foreach(src_file ${EXE_SOURCES})
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/source/controller/src/${src_file})
endforeach()

add_executable(${EXE} ${SOURCES})

target_compile_features(${EXE}
    PRIVATE
    c_std_99
)

target_compile_definitions(${EXE}
    PRIVATE
    _GNU_SOURCE
)

target_compile_options(${EXE}
    PRIVATE
    -Wall
    -Werror
)

target_include_directories(${EXE}
    PRIVATE
    ${PROJECT_SOURCE_DIR}/source/controller/include
    ${PROJECT_SOURCE_DIR}/source/libplatform/include
    ${PROJECT_SOURCE_DIR}/source/ieee1905/src/al/src_independent/extensions/map
    ${PROJECT_SOURCE_DIR}/source/ieee1905/src/factory/interfaces
    ${PROJECT_SOURCE_DIR}/source/ieee1905/src/factory/interfaces/extensions/map
    ${PROJECT_SOURCE_DIR}/source/ieee1905/src/common/interfaces
    PUBLIC ${LIBUBOX_INCLUDE_DIRS}
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/ccsp
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/include/dbus-1.0
    PUBLIC ${BSP_SYSROOTS_DIR}/usr/lib/dbus-1.0/include
)

target_link_libraries(${EXE}
    PRIVATE
	utils-static
	al-static
	factory-static
	common-static
	ssp-static
	-Wl,--gc-sections
)

install(TARGETS ${EXE}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
