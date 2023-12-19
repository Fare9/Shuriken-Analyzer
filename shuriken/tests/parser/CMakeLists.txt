if(DEX AND DEX_TESTS)
    message(STATUS "Compiling test parse-test-dex")
    configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/parse-test-dex.in
            ${CMAKE_CURRENT_SOURCE_DIR}/parse-test-dex.inc
    )

    add_executable(parse-test-dex
            ${CMAKE_CURRENT_SOURCE_DIR}/parse-test-dex.cpp
            $<TARGET_OBEJCTS:shuriken-obj>
            $<TARGET_OBJECTS:dex-obj>
    )

    target_link_libraries(parse-test-dex spdlog)

    add_test(NAME parse-test-dex
    COMMAND parse-test-dex)

endif ()