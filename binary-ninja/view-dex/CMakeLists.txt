CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

project(view-dex)

# --Binary Ninja API Setup-------------------------------------------
set (BINJA-API-STABLE-3.5      "59e569906828e91e4884670c2bba448702f5a31d")
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
    #add_definitions("-Wno-macro-redefined" "-Wno-deprecated-declarations" "-Wno-suggest-override" "-Wno-non-virtual-dtor")
    set(HEADLESS 1)
    add_subdirectory(
            ${binja-api_SOURCE_DIR}
            ${binja-api_BINARY_DIR}
    )
endif()

# --DexView-----------------------------------------------------------

include_directories(./inc)

set(CMAKE_CXX_STANDARD 20)

add_library(${PROJECT_NAME} SHARED  src/plugin.cpp
                                    src/dexview.cpp
                                    src/dexviewtype.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE binaryninjaapi)


target_include_directories(${PROJECT_NAME} PUBLIC ./inc)

