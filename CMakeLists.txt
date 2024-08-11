cmake_minimum_required(VERSION 3.5)


# Check if the FUZZBUILD flag is set
if(FUZZBUILD)
    set(CMAKE_C_COMPILER "afl-cc")
    set(CMAKE_CXX_COMPILER "afl-c++")
endif()

# Information from Shuriken project
project(
        ShurikenProject
        LANGUAGES CXX
        VERSION 0.0.1
        DESCRIPTION "Top folder from Shuriken project"
        HOMEPAGE_URL https://github.com/Fare9/Shuriken-Analyzer/
)


# Set CMake MacOS runtime path to find .so files on mac
set(CMAKE_MACOSX_RPATH 1)
# Append runtime path to find .so files on unix, needed before install
list( APPEND CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib" )
enable_testing()
add_subdirectory(externals/)
add_subdirectory(shuriken/)
add_subdirectory(shuriken-dump/)
