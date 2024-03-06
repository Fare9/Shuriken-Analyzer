if(DEX AND DEX_TESTS)
    configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.in
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.inc
    )

    # First Test Executable
    message(STATUS "Compiling test parse-test-dex")
    add_executable(parse-test-dex
            ${CMAKE_CURRENT_SOURCE_DIR}/parse-test-dex.cpp
    )

    target_include_directories(parse-test-dex
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(parse-test-dex shuriken)

    target_link_libraries(parse-test-dex shuriken)

    add_test(NAME parse-test-dex
            COMMAND parse-test-dex)

    # Second test
    message(STATUS "Compiling test headers-test-dex")
    add_executable(headers-test-dex
            ${CMAKE_CURRENT_SOURCE_DIR}/headers-test-dex.cpp
    )

    target_include_directories(headers-test-dex
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(headers-test-dex shuriken)

    target_link_libraries(headers-test-dex shuriken)

    add_test(NAME headers-test-dex
            COMMAND headers-test-dex)

    if(NOT CMAKE_C_COMPILER_LOADED)
        message(ERROR "Error you must provide a C compiler for testing files")
    else ()
        message(STATUS "C compiler ID: ${CMAKE_C_COMPILER_ID}")
        message(STATUS "C compiler version: ${CMAKE_C_COMPILER_VERSION}")
    endif ()

    # Third test
    message(STATUS "Compiling test core-api-test")
    add_executable(core-api-test
            ${CMAKE_CURRENT_SOURCE_DIR}/core-api-test.cpp
    )

    #set_target_properties(core-api-test PROPERTIES LANGUAGE C)
    #set_target_properties(core-api-test PROPERTIES LINKER_LANGUAGE C)

    target_include_directories(core-api-test
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(core-api-test shuriken)

    target_link_libraries(core-api-test shuriken)

    add_test(NAME core-api-test
            COMMAND core-api-test)
endif ()
