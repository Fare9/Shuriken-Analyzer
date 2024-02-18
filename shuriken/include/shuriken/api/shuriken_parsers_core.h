//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file shuriken_parsers_core.h
// @brief Shim in C for accessing the different data from ShurikenLib

#ifndef SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
#define SHURIKENLIB_SHURIKEN_PARSERS_CORE_H

#ifdef __cplusplus
#define SHURIKENCOREAPI extern "C"
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#else
#define SHURIKENCOREAPI
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#endif

extern "C" {

typedef void* hDexContext;

/// C - DEX part of the CORE API from ShurikenLib

SHURIKENCOREAPI hDexContext parse_dex(const char* filePath);
SHURIKENCOREAPI void destroy_dex(hDexContext context);

SHURIKENCOREAPI size_t get_number_of_strings(hDexContext context);
SHURIKENCOREAPI const char* get_string_by_id(hDexContext context, size_t i);


/// @brief DexTypes of the DVM we have by default fundamental,
/// classes and array DexTypes
enum htype_e
{
    FUNDAMENTAL,    //! fundamental type (int, float...)
    CLASS,          //! user defined class
    ARRAY,          //! an array type
    UNKNOWN         //! maybe wrong?
};

/// @brief enum with the fundamental DexTypes
enum hfundamental_e
{
    BOOLEAN,
    BYTE,
    CHAR,
    DOUBLE,
    FLOAT,
    INT,
    LONG,
    SHORT,
    VOID,
    NONE = 99
};

/// @brief Structure which keeps information from a field
/// this can be accessed from the class data
typedef struct hdvmfield_t_ {
    /// @brief Name of the field
    const char *name;
    /// @brief Type of the field
    htype_e type;
    /// @brief In case `type` == FUNDAMENTAL
    /// in case of ARRAY if the base type is
    /// a fundamental value, it contains that value
    hfundamental_e fundamental_value;
    /// @brief String value of the type
    const char * type_value;
    /// @brief access flags from the field
    uint16_t access_flags;
} hdvmfield_t;

/// @brief Structure which keeps information from a method
/// this can be accessed from the class data
typedef struct hdvmmethod_t_ {
    /// @brief name of the method
    const char * method_name;
    /// @brief prototype of the method
    const char * prototype;
    /// @brief access flags
    uint16_t access_flags;
    /// @brief number of registers
    uint32_t code_size;
    /// @brief pointer to a code buffer
    uint8_t * code;
    /// @brief Full Dalvik name
    const char * dalvik_name;
    /// @brief Demangled name
    const char * demangled_name;
} hdvmmethod_t;

/// @brief Structure representing the classes in the DEX file
typedef struct hdvmclass_t {
    /// @brief name of the class
    const char* class_name;
    /// @brief name of the super class
    const char* super_class;
    /// @brief name of the source file (if exists)
    const char* source_file;
    /// @brief access flags from the class
    uint16_t access_flags;
    /// @brief number of direct methods
    uint16_t direct_methods_size;
    /// @brief array of direct methods
    hdvmmethod_t *direct_methods;
    /// @brief number of virtual methods
    uint16_t virtual_methods_size;
    /// @brief array of virtual methods
    hdvmmethod_t *virtual_methods;
    /// @brief number of instance fields
    uint16_t instance_fields_size;
    /// @brief instance fields
    hdvmfield_t *instance_fields;
    /// @brief number of static fields
    uint16_t static_fields_size;
    /// @brief static fields
    hdvmfield_t *static_fields;
} hdvmclass_t;

SHURIKENCOREAPI uint16_t get_number_of_classes(hDexContext context);

SHURIKENCOREAPI hdvmclass_t * get_class_by_id(hDexContext context, uint16_t i);

};

#endif //SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
