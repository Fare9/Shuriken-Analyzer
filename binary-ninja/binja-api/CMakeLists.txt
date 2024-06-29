CMAKE_MINIMUM_REQUIRED(VERSION 3.14)

project(binja-api)

include(FetchContent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_PREFIX_PATH ${BN_QT})

# --Binary Ninja API Setup-------------------------------------------
set (BINJA-API-STABLE-3.5 "59e569906828e91e4884670c2bba448702f5a31d")
set (BINJA-API-STABLE-4.0.4958 "b7c8e9bfbae0eec8d7be47cd42f61c14542cc28c")
set (BINJA_API-VERSION ${BINJA-API-STABLE-4.0.4958})
message(STATUS "Using Binary API: ${BINJA_API-VERSION}")
FetchContent_Declare(
        binja-api

        GIT_REPOSITORY https://github.com/Vector35/binaryninja-api.git
        GIT_TAG ${BINJA_API-VERSION}
)
FetchContent_GetProperties(binja-api)
if(NOT binja-api_POPULATED)
    message(STATUS "Cloning Binary Ninja API")
    FetchContent_Populate(binja-api)
    if(MSVC)
        add_compile_options(/wd4005 /wd4996 /wd4244)
    endif()
    set(HEADLESS 1)
    add_subdirectory(
            ${binja-api_SOURCE_DIR}
            ${binja-api_BINARY_DIR}
    )
endif()