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