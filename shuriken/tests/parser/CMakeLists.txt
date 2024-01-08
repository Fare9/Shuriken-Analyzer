if(DEX AND DEX_TESTS)
    message(STATUS "Compiling test parse-test-dex")
    configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.in
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.inc
    )

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
endif ()
