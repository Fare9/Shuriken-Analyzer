//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dvm_types.h
// @brief DexTypes that can be used for the Dalvik Virtual Machine

#ifndef SHURIKENLIB_DVM_TYPES_H
#define SHURIKENLIB_DVM_TYPES_H

#include <iostream>
#include <cstdint>

namespace shuriken {
    namespace dex {
        static const std::uint32_t ENDIAN_CONSTANT = 0x12345678;
        static const std::uint32_t REVERSE_ENDIAN_CONSTANT = 0x78563412;
        static const std::uint32_t NO_INDEX = 0xFFFFFFFF;

        static const std::uint8_t dex_magic[] = {'d', 'e', 'x', '\n'};

        namespace TYPES {
            /// @brief Access flags used in class_def_item,
            /// encoded_field, encoded_method and InnerClass
            /// https://source.android.com/devices/tech/dalvik/dex-format#access-flags
            enum access_flags
            {
                NONE = 0x0,                         //! No access flags
                ACC_PUBLIC = 0x1,                   //! public type
                ACC_PRIVATE = 0x2,                  //! private type
                ACC_PROTECTED = 0x4,                //! protected type
                ACC_STATIC = 0x8,                   //! static (global) type
                ACC_FINAL = 0x10,                   //! final type (constant)
                ACC_SYNCHRONIZED = 0x20,            //! synchronized
                ACC_VOLATILE = 0x40,                //! Java volatile
                ACC_BRIDGE = 0x40,                  //!
                ACC_TRANSIENT = 0x80,               //!
                ACC_VARARGS = 0x80,                 //!
                ACC_NATIVE = 0x100,                 //! native type
                ACC_INTERFACE = 0x200,              //! interface type
                ACC_ABSTRACT = 0x400,               //! abstract type
                ACC_STRICT = 0x800,                 //!
                ACC_SYNTHETIC = 0x1000,             //!
                ACC_ANNOTATION = 0x2000,            //!
                ACC_ENUM = 0x4000,                  //! enum type
                UNUSED = 0x8000,                    //!
                ACC_CONSTRUCTOR = 0x10000,          //! constructor type
                ACC_DECLARED_SYNCHRONIZED = 0x20000 //!
            };

            /// @brief Enumeration used for the types.
            enum class value_format
            {
                VALUE_BYTE = 0x0,           //! ubyte[1]
                VALUE_SHORT = 0x2,          //! ubyte[size]
                VALUE_CHAR = 0x3,           //! ubyte[size]
                VALUE_INT = 0x4,            //! ubyte[size]
                VALUE_LONG = 0x6,           //! ubyte[size]
                VALUE_FLOAT = 0x10,         //! ubyte[size]
                VALUE_DOUBLE = 0x11,        //! ubyte[size]
                VALUE_METHOD_TYPE = 0x15,   //! ubyte[size]
                VALUE_METHOD_HANDLE = 0x16, //! ubyte[size]
                VALUE_STRING = 0x17,        //! ubyte[size]
                VALUE_TYPE = 0x18,          //! ubyte[size]
                VALUE_FIELD = 0x19,         //! ubyte[size]
                VALUE_METHOD = 0x1A,        //! ubyte[size]
                VALUE_ENUM = 0x1B,          //! ubyte[size]
                VALUE_ARRAY = 0x1C,         //! EncodedArray
                VALUE_ANNOTATION = 0x1D,    //! EncodedAnnotation
                VALUE_NULL = 0x1E,          //! None
                VALUE_BOOLEAN = 0x1F        //! None
            };
        }

        class Utils {
        public:
            static std::string get_types_as_string(TYPES::access_flags ac);
        };
    }
}
#endif //SHURIKENLIB_DVM_TYPES_H
