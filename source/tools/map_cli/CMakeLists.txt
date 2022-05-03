##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

add_executable(map_cli map_cli.c)

target_compile_features(map_cli
    PRIVATE
    c_std_99
)

target_compile_definitions(map_cli
    PRIVATE
    _GNU_SOURCE
)

target_include_directories(map_cli
    PRIVATE
    ${CMAKE_SOURCE_DIR}/source/libplatform/include
)

target_link_libraries(map_cli
    PRIVATE
	-Wl,--gc-sections
)

install(TARGETS
    map_cli
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
