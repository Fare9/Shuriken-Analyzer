cmake_minimum_required(VERSION 3.5)

option(BUILD_BINJA_PLUGIN "Build the binary ninja plugin set" OFF)

# Information from Shuriken project
project(
        ShurikenProject
        LANGUAGES CXX
        VERSION 0.0.1
        DESCRIPTION "Top folder from Shuriken project"
        HOMEPAGE_URL https://github.com/Fare9/Shuriken-Analyzer/
)

add_subdirectory(shuriken/)
add_subdirectory(shuriken-dump/)
if (BUILD_BINJA_PLUGIN)
        add_subdirectory(binary-ninja/)
endif (BUILD_BINJA_PLUGIN)