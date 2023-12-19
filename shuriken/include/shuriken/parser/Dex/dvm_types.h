//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dvm_types.h
// @brief Types that can be used for the Dalvik Virtual Machine

#ifndef SHURIKENLIB_DVM_TYPES_H
#define SHURIKENLIB_DVM_TYPES_H

#include <iostream>

namespace shuriken {
    namespace dex {
        static const std::uint32_t ENDIAN_CONSTANT = 0x12345678;
        static const std::uint32_t REVERSE_ENDIAN_CONSTANT = 0x78563412;
        static const std::uint32_t NO_INDEX = 0xFFFFFFFF;

        static const std::uint8_t dex_magic[] = {'d', 'e', 'x', '\n'};

    }
}
#endif //SHURIKENLIB_DVM_TYPES_H
