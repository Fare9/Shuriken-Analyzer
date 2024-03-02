target_sources(dex-obj PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/dex_c_core_api.cpp
        ${CMAKE_CURRENT_LIST_DIR}/apk_c_core_api.cpp
        ${CMAKE_CURRENT_LIST_DIR}/dex_cpp_core_api.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ShurikenDex.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ShurikenPrototype.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ShurikenClassField.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ShurikenClassMethod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ShurikenDexClass.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ShurikenClassManager.cpp
)