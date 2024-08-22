
cmake_minimum_required(VERSION 3.5)

include(FetchContent)

set(FETCHCONTENT_QUIET off)

# check if we have connection using PING
if(CMAKE_HOST_WIN32)
execute_process(
        COMMAND ping www.google.com -n 2
        ERROR_QUIET
        RESULT_VARIABLE NO_CONNECTION
)
else()
execute_process(
        COMMAND ping www.google.com -c 2
        ERROR_QUIET
        RESULT_VARIABLE NO_CONNECTION
)
endif()

if(NOT NO_CONNECTION EQUAL 0)
    set(FETCHCONTENT_FULLY_DISCONNECTED ON)
    message(WARNING "Fetch offline mode: requires already populated _deps")
else()
    set(FETCHCONTENT_FULLY_DISCONNECTED OFF)
    message(STATUS "Fetch will be used to download external dependencies")
endif()
#
if (GITHUB_ACTION)
    message(WARNING "Running as a github action, download fetch the content")
    set(FETCHCONTENT_FULLY_DISCONNECTED OFF)
endif ()

# ------------------------------------
# Download the Logging utility from spdlog
# repo
# ------------------------------------
FetchContent_Declare(
        extern_spdlog

        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.12.0
)

FetchContent_GetProperties(extern_spdlog)

if(NOT extern_spdlog_POPULATED)
    message(STATUS "Cloning spdlog")
    FetchContent_Populate(extern_spdlog)
    set(SPDLOG_BUILD_SHARED OFF)
    add_subdirectory(
            ${extern_spdlog_SOURCE_DIR}
            ${extern_spdlog_BINARY_DIR}
    )
endif()


set_target_properties(spdlog
        PROPERTIES
        POSITION_INDEPENDENT_CODE 1
)

# Make the project available
FetchContent_MakeAvailable(extern_spdlog)

# ------------------------------------
# Download the printing utility fmt
# ------------------------------------
FetchContent_Declare(
        fmt

        GIT_REPOSITORY https://github.com/fmtlib/fmt
        GIT_TAG 10.1.1
)

FetchContent_GetProperties(fmt)

if(NOT fmt_POPULATED)
    message(STATUS "Cloning fmt")
    FetchContent_Populate(fmt)
    add_subdirectory(
            ${fmt_SOURCE_DIR}
            ${fmt_BINARY_DIR}
    )
endif()

# Make the project available
FetchContent_MakeAvailable(fmt)


# ------------------------------------
# Download the zip libary
# ------------------------------------

FetchContent_Declare(
        libzip
        GIT_REPOSITORY https://github.com/nih-at/libzip.git
        GIT_TAG        main  # Or a specific version tag
)

FetchContent_GetProperties(libzip)

if(NOT libzip_POPULATED)
    message(STATUS "Cloning libzip")
    FetchContent_Populate(libzip)
    add_subdirectory(
            ${libzip_SOURCE_DIR}
            ${libzip_BINARY_DIR}
    )
endif()

FetchContent_MakeAvailable(libzip)

