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

add_executable(shuriken-dump
shuriken-dump.cpp
)

target_link_libraries(shuriken-dump
    PRIVATE
        shuriken
        fmt
)

# Assuming this variable points to your project's include directory
set(SHURIKEN_DUMP_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Install the Shuriken library's binary
install(TARGETS shuriken-dump
        RUNTIME DESTINATION ${binary_install_path}
)

# Install the Shuriken library's header files
install(DIRECTORY ${SHURIKEN_DUMP_INCLUDE_PATH}/
        DESTINATION ${include_install_path}
        FILES_MATCHING PATTERN "*.h*"
)
