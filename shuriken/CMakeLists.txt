cmake_minimum_required(VERSION 3.5)

# Information from Shuriken project
project(
        ShurikenLib
        LANGUAGES CXX
        VERSION 0.0.1
        DESCRIPTION "Library for the analysis of bytecodes"
        HOMEPAGE_URL https://github.com/Fare9/Shuriken-Analyzer/
)

##############################################################
# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Compiler for the project
if(CMAKE_CXX_COMPILER_LOADED)
    message(STATUS "C++ compiler ID: ${CMAKE_CXX_COMPILER_ID}")
    message(STATUS "C++ compiler version: ${CMAKE_CXX_COMPILER_VERSION}")
endif()

# Build type
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Build type not set, setting to Release")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

# for debug configuration set specific flags
if(NOT WIN32)
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g -O0 -DNDEBUG")
endif()
##############################################################

# options for compilation, Shuriken will be intended to provide the user
# with the options to compile only part of the project
option(DEX "Disable the DEX analysis from the library (enable by default)" ON)
option(DEX_TESTS "Compile all the tests for DEX files" OFF)

# Variables that need to be set for compiling dalvik files
set(JAVAC_BINARY "" CACHE FILEPATH "Path to javac binary for compiling java files")
set(D8_BINARY "" CACHE FILEPATH "Path to d8 binary for compiling dex files")

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")


# include the externals
add_subdirectory(external)

set_target_properties(spdlog
        PROPERTIES
        POSITION_INDEPENDENT_CODE 1
)


# Shuriken will contain only the basic classes, nothing more
# the analyses for the different files are included optionally
# we will include all the content in an object file
message(STATUS "Generating Shuriken object files")

add_library(shuriken-obj
        OBJECT
)

set_target_properties(shuriken-obj
        PROPERTIES
        POSITION_INDEPENDENT_CODE 1
)

# subdirectories for shuriken
add_subdirectory(lib/common/)
target_link_libraries(shuriken-obj PRIVATE spdlog::spdlog)


# more information of object files
list(APPEND LIB_MODULES
        $<TARGET_OBJECTS:shuriken-obj>
)

# Compile the object files for DEX
if (DEX)
    message(STATUS "Generating Shuriken DEX object files")

    add_library(dex-obj
            OBJECT
    )
    target_link_libraries(dex-obj PRIVATE spdlog::spdlog)

    set_target_properties(dex-obj
            PROPERTIES
            POSITION_INDEPENDENT_CODE 1
    )

    add_subdirectory(lib/parser/Dex)

    target_include_directories(dex-obj
            BEFORE
            PUBLIC ${SHURIKEN_INCLUDE_PATH}
    )

    list(APPEND LIB_MODULES
            $<TARGET_OBJECTS:dex-obj>
    )
endif ()

message(STATUS "Generating Shuriken shared library")
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
add_library(shuriken SHARED
        ${LIB_MODULES}
)

message(STATUS "Linking libraries into Shuriken library")

target_link_libraries(shuriken PRIVATE spdlog::spdlog)
target_include_directories(shuriken
        PUBLIC
        "${CMAKE_SOURCE_DIR}/shuriken/include/"
)
#############################################################
include(CTest)

if (DEX_TESTS AND JAVAC_BINARY STREQUAL "" AND D8_BINARY STREQUAL "")
    message(STATUS "Test option used but not compilers for DEX provided, using precompiled DEX")
    set(DEX_FILES_FOLDER
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/compiled/")
else ()
    message(STATUS "Test option used and compilers path provided, compiling DEX files")
    set(DEX_FILES_FOLDER
        "${CMAKE_CURRENT_BINARY_DIR}/tests/code/java/")
    set(COMPILE_DEX_FILES ON)
endif ()

message(STATUS "Path to DEX Folder: ${DEX_FILES_FOLDER}")
add_subdirectory(tests)
enable_testing()
