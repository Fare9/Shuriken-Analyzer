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

target_link_libraries(shuriken-dumb
    PRIVATE
        shuriken
        spdlog
        fmt
)

# Assuming this variable points to your project's include directory
set(SHURIKEN_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Check for operating system and set install paths accordingly
set(include_install_path "/usr/local/include") # Default path
set(binary_install_path "/usr/local/bin") # Default path

if(APPLE)
    find_program(HOMEBREW_FOUND brew)
    if(HOMEBREW_FOUND)
        execute_process(COMMAND brew --prefix
                        OUTPUT_VARIABLE HOMEBREW_PREFIX
                        OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(include_install_path "${HOMEBREW_PREFIX}/include")
        set(binary_install_path "${HOMEBREW_PREFIX}/bin")
    endif()
    set_target_properties(shuriken-dump PROPERTIES
    INSTALL_RPATH "${library_install_path}"
)
elseif(UNIX AND NOT APPLE) # Explicitly differentiate UNIX from APPLE
    # Linux specific paths (already set as default)
endif()



# Install the Shuriken library's binary
install(TARGETS shuriken-dump

        RUNTIME DESTINATION ${binary_install_path}
)

# Install the Shuriken library's header files
install(DIRECTORY ${SHURIKEN_INCLUDE_PATH}/
        DESTINATION ${include_install_path}
        FILES_MATCHING PATTERN "*.h*"
)
