CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

project(view-dex)

include_directories(./inc)

set(CMAKE_CXX_STANDARD 20)

add_library(${PROJECT_NAME} SHARED  src/plugin.cpp
                                    src/dexview.cpp
                                    src/dexviewtype.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE binaryninjaapi shuriken)


target_include_directories(${PROJECT_NAME} PUBLIC ./inc)

