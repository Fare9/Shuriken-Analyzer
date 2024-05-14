if(DEX AND DEX_TESTS AND COMPILE_DEX_FILES)
    message(STATUS "Compiling DEX files")

    if(JAVAC_BINARY STREQUAL "")
        message(FATAL_ERROR "JAVAC_BINARY is not set")
    endif()

    if(D8_BINARY STREQUAL "")
        message(FATAL_ERROR "D8_BINARY is not set")
    endif()

    set(JAVA_FILES
            _cast
            _double
            _exception
            _float
            _instance
            _int
            _long
            _loop
            _null
            _pi
            _switch
            _xrefs
            DexParserTest
    )

    set(D8_RESULTS)
    foreach (file ${JAVA_FILES})
        message(STATUS "Compiling ${file}.java -> ${file}.dex")
        add_custom_command(
                OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file}.dex
                DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}.java
                DEPENDS ${PREV_DEX_FILE}
                COMMAND ${JAVAC_BINARY} --release 8 ${CMAKE_CURRENT_SOURCE_DIR}/${file}.java
                COMMAND mv ${CMAKE_CURRENT_SOURCE_DIR}/${file}*.class ${CMAKE_CURRENT_BINARY_DIR}
                COMMAND ${D8_BINARY} ${CMAKE_CURRENT_BINARY_DIR}/${file}*.class --output ${CMAKE_CURRENT_BINARY_DIR}
                COMMAND mv ${CMAKE_CURRENT_BINARY_DIR}/classes.dex ${CMAKE_CURRENT_BINARY_DIR}/${file}.dex
        )
        set(PREV_DEX_FILE ${CMAKE_CURRENT_BINARY_DIR}/${file}.dex)
        list(APPEND D8_RESULTS ${CMAKE_CURRENT_BINARY_DIR}/${file}.dex)
    endforeach ()

    # Create a single custom target for all DEX files
    add_custom_target(DalvikFiles ALL
            DEPENDS ${D8_RESULTS}
    )

endif ()
