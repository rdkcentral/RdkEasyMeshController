##########################################################################
# Copyright (c) 2019-2024 AirTies Wireless Networks
#
# Licensed under the BSD+Patent License.
##########################################################################

function(SETUP_UNIT_TEST_LIB)
    add_library(unit_test
                STATIC
                ${ARGN}
               )

    target_compile_definitions(unit_test
        PRIVATE ${CONDUCTOR_UNIT_TEST_BUILD_FLAGS}
    )

    target_include_directories(unit_test
                               PRIVATE ${UNIT_TEST_INCLUDES}
                              )
endfunction() # SETUP_UNIT_TEST_LIB

function(SETUP_UNIT_TEST _name)
    set(SRCS
        test_${_name}.c
        ${ARGN}
    )

    get_filename_component(UNIT_TEST_DIR ${CMAKE_CURRENT_LIST_DIR} NAME)
    set(UNIT_TEST_NAME unittest_${UNIT_TEST_DIR}_${_name})

    add_executable(${UNIT_TEST_NAME}
        ${SRCS}
    )

    target_compile_definitions(${UNIT_TEST_NAME}
        PRIVATE DATA_DIR="${CMAKE_CURRENT_LIST_DIR}/data"
        ${UNIT_TEST_EXTRA_DEFINES}
    )

    target_include_directories(${UNIT_TEST_NAME}
        PRIVATE ${UNIT_TEST_INCLUDES}
    )

    target_link_libraries(${UNIT_TEST_NAME}
        ${UNIT_TEST_LIBS}
    )

    #For coverage only include files outside test dir
    foreach(SRC ${SRCS})
        if (${SRC} MATCHES test/../)
            set(COVERAGE_SRCS ${COVERAGE_SRCS} ${SRC})
        endif()
    endforeach(SRC)

    set_source_files_properties(
        ${COVERAGE_SRCS}
        PROPERTIES
        COMPILE_FLAGS ${CMAKE_C_FLAGS_COVERAGE}
    )

    set_target_properties(${UNIT_TEST_NAME}
        PROPERTIES
        LINK_FLAGS_DEBUG --coverage
    )

    add_test(NAME ${UNIT_TEST_NAME} COMMAND ${UNIT_TEST_NAME})

    setup_target_for_coverage(${UNIT_TEST_NAME}_coverage "${CMAKE_CTEST_COMMAND}" coverage_report_${_name} "-VV;-R;${UNIT_TEST_NAME}")
    if(VALGRIND_EXEC)
        add_custom_target(${UNIT_TEST_NAME}_memcheck
            ${VALGRIND_EXEC} ${MEMORYCHECK_DEV_COMMAND_OPTIONS} ./${UNIT_TEST_NAME}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
    endif()
endfunction() # SETUP_UNIT_TEST
