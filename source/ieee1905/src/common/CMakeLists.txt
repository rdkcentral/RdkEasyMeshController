##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

project(common
    DESCRIPTION "Easy-mesh controller"
    LANGUAGES C
)

set(COMMON common)
set(COMMONSTATIC common-static)

set(COMMON_INDEPENDENT_SOURCES
    src_independent/utils.c
)

set(COMMON_INDEPENDENT_INCLUDES
    PUBLIC ${PROJECT_SOURCE_DIR}/interfaces
    PRIVATE ${SYSTEM_INCLUDES}
)

set(COMMON_PLATFORM_SOURCES
    src_linux/platform.c
)

set(COMMON_PLATFORM_INCLUDES
    PUBLIC ${PROJECT_SOURCE_DIR}/interfaces
    PRIVATE ${SYSTEM_INCLUDES}
)

set(COMMON_COMPILE_OPTIONS
	-fPIC
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

set(COMMON_LIBRARIES
    -Wl,--gc-sections
# uncomment if you want to see which symbols are GC'd
#    -Wl,--print-gc-sections
)

# Library objects
add_library(COMMON_INDEPENDENT-objs OBJECT ${COMMON_INDEPENDENT_SOURCES})
target_compile_options(COMMON_INDEPENDENT-objs PRIVATE ${COMMON_COMPILE_OPTIONS})
target_include_directories(COMMON_INDEPENDENT-objs ${COMMON_INDEPENDENT_INCLUDES})

# Library objects
add_library(COMMON_PLATFORM-objs OBJECT ${COMMON_PLATFORM_SOURCES})
target_compile_options(COMMON_PLATFORM-objs PRIVATE ${COMMON_COMPILE_OPTIONS})
target_include_directories(COMMON_PLATFORM-objs ${COMMON_PLATFORM_INCLUDES})

# Dynamic library
add_library(${COMMON}
    SHARED
    $<TARGET_OBJECTS:COMMON_INDEPENDENT-objs>
    $<TARGET_OBJECTS:COMMON_PLATFORM-objs>
)
target_link_libraries(${COMMON} ${COMMON_LIBRARIES})

# Static library
add_library(${COMMONSTATIC}
    STATIC
    $<TARGET_OBJECTS:COMMON_INDEPENDENT-objs>
    $<TARGET_OBJECTS:COMMON_PLATFORM-objs>
)
set_target_properties(${COMMONSTATIC} PROPERTIES OUTPUT_NAME ${COMMON})
target_link_libraries(${COMMONSTATIC} ${COMMON_LIBRARIES})

# Install header file(s)
#install(DIRECTORY
#    ${PROJECT_SOURCE_DIR}/interfaces
#    DESTINATION include/ieee1905
#)

# Install library
#install(TARGETS ${LIBSTATIC}
#    RUNTIME DESTINATION bin
#    LIBRARY DESTINATION lib
#    ARCHIVE DESTINATION lib
#)
