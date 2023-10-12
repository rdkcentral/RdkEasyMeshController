##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

project(factory
    DESCRIPTION "ieee1905 factory component"
    LANGUAGES C
)

set(FACTORY factory)
set(FACTORYSTATIC factory-static)

set(FACTORY_INDEPENDENT_SOURCES
    src_independent/1905_cmdus.c
    src_independent/1905_tlvs.c
    src_independent/lldp_payload.c
    src_independent/lldp_tlvs.c
    src_independent/media_specific_blobs.c
    src_independent/extensions/map/map_r1_tlvs.c
    src_independent/extensions/map/map_r2_tlvs.c
    src_independent/extensions/map/map_r3_tlvs.c
)

set(FACTORY_INDEPENDENT_INCLUDES
    PRIVATE ${PROJECT_SOURCE_DIR}/src_independent
    PUBLIC ${PROJECT_SOURCE_DIR}/interfaces
    PUBLIC ${PROJECT_SOURCE_DIR}/interfaces/extensions/map
    PRIVATE ${COMMON_INCLUDES}
    PRIVATE ${SYSTEM_INCLUDES}
)

set(FACTORY_LIBRARIES
    -Wl,--gc-sections
)

# Library objects
add_library(FACTORY_INDEPENDENT-objs OBJECT ${FACTORY_INDEPENDENT_SOURCES})
target_include_directories(FACTORY_INDEPENDENT-objs ${FACTORY_INDEPENDENT_INCLUDES})

# Dynamic library
add_library(${FACTORY}
    SHARED
    $<TARGET_OBJECTS:FACTORY_INDEPENDENT-objs>
)
target_link_libraries(${FACTORY} ${FACTORY_LIBRARIES})

# Static library
add_library(${FACTORYSTATIC}
    STATIC
    $<TARGET_OBJECTS:FACTORY_INDEPENDENT-objs>
)
set_target_properties(${FACTORYSTATIC} PROPERTIES OUTPUT_NAME ${FACTORY})
target_link_libraries(${FACTORYSTATIC} ${FACTORY_LIBRARIES})

