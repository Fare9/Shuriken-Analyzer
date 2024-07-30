if(DEX AND DEX_TESTS)
    configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.in
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.inc
    )

    # First Test Executable
    message(STATUS "Compiling test xrefs-analysis")
    add_executable(xrefs-analysis
            xrefs-analysis.cpp
    )

    target_include_directories(xrefs-analysis
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(xrefs-analysis shuriken)

    target_link_libraries(xrefs-analysis shuriken)

    add_test(NAME xrefs-analysis
            COMMAND xrefs-analysis)

    # Core API test for analysis
    message(STATUS "Compiling test core-api-test-analysis")
    add_executable(core-api-test-analysis
            core-api-test-analysis.cpp
    )

    target_include_directories(core-api-test-analysis
        BEFORE
        PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(core-api-test-analysis shuriken)

    target_link_libraries(core-api-test-analysis shuriken)

    add_test(NAME core-api-test-analysis
            COMMAND core-api-test-analysis)
endif()
