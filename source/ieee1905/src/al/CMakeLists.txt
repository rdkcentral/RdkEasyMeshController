##########################################################################
# Copyright (c) 2021-2022 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

project(al
    DESCRIPTION "ieee al component"
    LANGUAGES C
)

set(AL al)
set(ALSTATIC al-static)

set(AL_INDEPENDENT_SOURCES
    src_independent/al_datamodel.c
    src_independent/al_entity.c
    src_independent/al_recv.c
    src_independent/al_send.c
    src_independent/al_utils.c
    src_independent/al_wsc.c
    src_independent/extensions/map/i1905.c
)

set(AL_INDEPENDENT_INCLUDES
    PRIVATE ${PROJECT_SOURCE_DIR}/src_independent
    PRIVATE ${PROJECT_SOURCE_DIR}/src_independent/extensions/map
    PUBLIC ${PROJECT_SOURCE_DIR}/internal_interfaces
    PRIVATE ${COMMON_INCLUDES}
    PRIVATE ${FACTORY_INCLUDES}
    PRIVATE ${SYSTEM_INCLUDES}
)

set(AL_PLATFORM_SOURCES
    src_linux/platform_crypto.c
    src_linux/platform_interfaces.c
    src_linux/platform_os.c
)

set(AL_PLATFORM_INCLUDES
    PRIVATE ${PROJECT_SOURCE_DIR}/src_linux
    PRIVATE ${PROJECT_SOURCE_DIR}/src_independent
    PRIVATE ${PROJECT_SOURCE_DIR}/src_independent/extensions/map
    PUBLIC ${PROJECT_SOURCE_DIR}/internal_interfaces
    PRIVATE ${COMMON_INCLUDES}
    PRIVATE ${FACTORY_INCLUDES}
    PRIVATE ${SYSTEM_INCLUDES}
    PRIVATE ${OPENSSL_INCLUDE_DIR}
)

set(AL_LIBRARIES
    ${OPENSSL_LIBRARIES}
    -Wl,--gc-sections
)

# Library objects
add_library(AL_INDEPENDENT-objs OBJECT ${AL_INDEPENDENT_SOURCES})
target_include_directories(AL_INDEPENDENT-objs ${AL_INDEPENDENT_INCLUDES})
get_property(dirs TARGET AL_INDEPENDENT-objs PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()

# Library objects
add_library(AL_PLATFORM-objs OBJECT ${AL_PLATFORM_SOURCES})
target_include_directories(AL_PLATFORM-objs ${AL_PLATFORM_INCLUDES})
get_property(dirs TARGET AL_PLATFORM-objs PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()

# Dynamic library
add_library(${AL}
    SHARED
    $<TARGET_OBJECTS:AL_INDEPENDENT-objs>
    $<TARGET_OBJECTS:AL_PLATFORM-objs>
)
target_link_libraries(${AL} ${AL_LIBRARIES})

# Static library
add_library(${ALSTATIC}
    STATIC
    $<TARGET_OBJECTS:AL_INDEPENDENT-objs>
    $<TARGET_OBJECTS:AL_PLATFORM-objs>
)
set_target_properties(${ALSTATIC} PROPERTIES OUTPUT_NAME ${AL})
target_link_libraries(${ALSTATIC} ${AL_LIBRARIES})

