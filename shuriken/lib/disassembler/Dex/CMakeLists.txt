target_sources(dex-obj PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/dex_instructions.cpp
        ${CMAKE_CURRENT_LIST_DIR}/disassembled_method.cpp
        ${CMAKE_CURRENT_LIST_DIR}/internal_disassembler.cpp
        ${CMAKE_CURRENT_LIST_DIR}/linear_sweep_disassembler.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_disassembler.cpp
)