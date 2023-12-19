cmake_minimum_required(VERSION 3.5)

include(FetchContent)

set(FETCHCONTENT_QUIET off)

# check if we have connection using PING
execute_process(
        COMMAND ping www.google.com -c 2
        ERROR_QUIET
        RESULT_VARIABLE NO_CONNECTION
)

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
        spdlog

        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.12.0
)

FetchContent_GetProperties(spdlog)

if(NOT spdlog_POPULATED)
    message(STATUS "Cloning spdlog")
    FetchContent_Populate(spdlog)
    add_subdirectory(
            ${spdlog_SOURCE_DIR}
            ${spdlog_BINARY_DIR}
    )
endif()


# Make the project available
FetchContent_MakeAvailable(spdlog)