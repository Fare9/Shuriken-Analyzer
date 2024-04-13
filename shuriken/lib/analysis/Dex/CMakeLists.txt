target_sources(dex-obj PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/external_method.cpp
        ${CMAKE_CURRENT_LIST_DIR}/external_class.cpp
        ${CMAKE_CURRENT_LIST_DIR}/basic_blocks.cpp
        ${CMAKE_CURRENT_LIST_DIR}/field_analysis.cpp
        ${CMAKE_CURRENT_LIST_DIR}/string_analysis.cpp
        ${CMAKE_CURRENT_LIST_DIR}/method_analysis.cpp
        ${CMAKE_CURRENT_LIST_DIR}/class_analysis.cpp
)