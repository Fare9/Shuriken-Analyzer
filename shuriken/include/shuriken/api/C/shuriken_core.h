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

/// @brief main method from the DEX Core API
/// it parses the DEX file and it retrieves a context object
/// @param filePath path to the DEX file to analyze
/// @return context object to obtain information from the DEX file
SHURIKENCOREAPI hDexContext parse_dex(const char* filePath);

/// @brief Since the context object use dynamic memory this method
/// will properly destroy the object.
/// @param context object to destroys
SHURIKENCOREAPI void destroy_dex(hDexContext context);

/// @brief Get the number of strings from the DEX file
/// @param context from the DEX file
/// @return number of strings
SHURIKENCOREAPI size_t get_number_of_strings(hDexContext context);

/// @brief get one of the strings by the id
/// @param context from where to retrieve the string
/// @param i id of the string to retrieve
/// @return string from the id
SHURIKENCOREAPI const char* get_string_by_id(hDexContext context, size_t i);

/// @brief Get the number of classes from the DEX file
/// @param context dex from where to retrieve the number of classes
/// @return number of classes
SHURIKENCOREAPI uint16_t get_number_of_classes(hDexContext context);

/// @brief Get a class structure given an ID
/// @param context DEX from where to retrieve the class
/// @param i id of the class to retrieve
/// @return class from the DEX file
SHURIKENCOREAPI hdvmclass_t * get_class_by_id(hDexContext context, uint16_t i);

/// @brief Get a method structure given a full dalvik name.
/// @param method_name LclassName;->methodName(parameters)RetType
/// @return pointer to hdvmmethod_t, null if the method does not exist
SHURIKENCOREAPI hdvmmethod_t * get_method_by_name(hDexContext context, const char *method_name);


};

#endif //SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
