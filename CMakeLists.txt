cmake_minimum_required(VERSION 3.5)

# Information from Shuriken project
project(
        ShurikenProject
        LANGUAGES CXX
        VERSION 0.0.1
        DESCRIPTION "Top folder from Shuriken project"
        HOMEPAGE_URL https://github.com/Fare9/Shuriken-Analyzer/
)


enable_testing()
include(cmake/cmake_install_uninstall.cmake)
add_subdirectory(externals/)
add_subdirectory(shuriken/)
add_subdirectory(shuriken-dump/)
