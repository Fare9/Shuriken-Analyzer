if(DEX AND DEX_TESTS)
    configure_file(
            dex-files-folder.in
            dex-files-folder.inc
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

    
    # Third test, loops
    message(STATUS "Compiling test test-code-with-loops")
    add_executable(test-code-with-loops
            test-code-with-loops.cpp
    )

    target_include_directories(test-code-with-loops
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(test-code-with-loops shuriken)

    target_link_libraries(test-code-with-loops shuriken)

    add_test(NAME test-code-with-loops
            COMMAND test-code-with-loops)

endif()
