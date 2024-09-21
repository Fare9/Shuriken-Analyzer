if(DEX AND DEX_TESTS)
    configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.in
            ${CMAKE_CURRENT_SOURCE_DIR}/dex-files-folder.inc
    )

    # Load zip test
    message(STATUS "Compiling test analyze-simple-zip")
    add_executable(analyze-simple-zip
            ${CMAKE_CURRENT_SOURCE_DIR}/analyze-simple-zip.cpp
    )

    target_include_directories(analyze-simple-zip
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(analyze-simple-zip shuriken)

    target_link_libraries(analyze-simple-zip shuriken)

    add_test(NAME analyze-simple-zip
            COMMAND analyze-simple-zip)

    # Load core API
    message(STATUS "Compiling test core-api-test")
    add_executable(apk-core-api-test
            ${CMAKE_CURRENT_SOURCE_DIR}/apk-core-api-test.cpp
    )

    target_include_directories(apk-core-api-test
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    # Add dependency on shuriken library
    add_dependencies(apk-core-api-test shuriken)

    target_link_libraries(apk-core-api-test shuriken)

    add_test(NAME apk-core-api-test
            COMMAND apk-core-api-test)
endif()