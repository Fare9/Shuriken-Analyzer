target_sources(dex-obj PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/parser.cpp
        ${CMAKE_CURRENT_LIST_DIR}/header.cpp
        ${CMAKE_CURRENT_LIST_DIR}/mapitem.cpp
        ${CMAKE_CURRENT_LIST_DIR}/strings.cpp
        ${CMAKE_CURRENT_LIST_DIR}/types.cpp
        ${CMAKE_CURRENT_LIST_DIR}/protos.cpp
        ${CMAKE_CURRENT_LIST_DIR}/fields.cpp
        ${CMAKE_CURRENT_LIST_DIR}/methods.cpp
        ${CMAKE_CURRENT_LIST_DIR}/annotations.cpp
        ${CMAKE_CURRENT_LIST_DIR}/encoded.cpp
        ${CMAKE_CURRENT_LIST_DIR}/classes.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dvm_types.cpp
)