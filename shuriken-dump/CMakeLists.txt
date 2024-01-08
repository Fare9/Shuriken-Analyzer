cmake_minimum_required(VERSION 3.5)

# Information from Shuriken project
project(
        Shuriken-dump
        LANGUAGES CXX
        VERSION 0.0.1
        DESCRIPTION "Simple command line tool to dump information from analyzed files"
        HOMEPAGE_URL https://github.com/Fare9/Shuriken-Analyzer/
)

##############################################################
# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(external/)

add_executable(shuriken-dump
shuriken-dump.cpp
)

target_link_libraries(shuriken-dump
    PRIVATE
        shuriken
        spdlog
        fmt
)

target_include_directories(shuriken-dump
    PRIVATE
        "${CMAKE_SOURCE_DIR}/shuriken/include/"
)