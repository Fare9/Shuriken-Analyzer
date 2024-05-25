if(DEX AND DEX_TESTS)
    configure_file(
            dex-files-folder.in
            dex-files-folder.inc
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
endif()