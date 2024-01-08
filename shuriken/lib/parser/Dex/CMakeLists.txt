target_sources(dex-obj PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/parser.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_header.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_mapitem.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_strings.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_types.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_protos.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_fields.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_methods.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_annotations.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_encoded.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_classes.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dvm_types.cpp
)