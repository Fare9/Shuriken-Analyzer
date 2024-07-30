if(DEX AND DEX_TESTS)
    configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.in
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.inc
    )

    # First Test Executable
    message(STATUS "Compiling test parse-test-dex")
    add_executable(test-code-with-exceptions
            test-code-with-exceptions.cpp
    )

    target_include_directories(test-code-with-exceptions
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(test-code-with-exceptions shuriken)

    target_link_libraries(test-code-with-exceptions shuriken)

    add_test(NAME test-code-with-exceptions
            COMMAND test-code-with-exceptions)


    # Second Test Executable
    message(STATUS "Compiling test parse-test-dex")
    add_executable(test-code-with-switch
            test-code-with-switch.cpp
    )

    target_include_directories(test-code-with-switch
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(test-code-with-switch shuriken)

    target_link_libraries(test-code-with-switch shuriken)

    add_test(NAME test-code-with-switch
            COMMAND test-code-with-switch)

    # Core Disassembler API
    message(STATUS "Compiling test core-api-test-disassembler")
    add_executable(core-api-test-disassembler
            core-api-test-disassembler.cpp
    )

    target_include_directories(core-api-test-disassembler
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(core-api-test-disassembler shuriken)

    target_link_libraries(core-api-test-disassembler shuriken)

    add_test(NAME core-api-test-disassembler
        COMMAND core-api-test-disassembler)
endif()
