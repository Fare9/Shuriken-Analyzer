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

typedef void* hDexParser;

/// C - DEX part of the CORE API from ShurikenLib

SHURIKENCOREAPI hDexParser parse_dex(const char* filePath);
SHURIKENCOREAPI void destroy_dex(hDexParser parser);

#pragma pack(1)
/// @brief Structure with the definition of the DEX header
/// all these values are later used for parsing the other
/// headers from DEX
typedef struct h_dex_header_t
{
    uint8_t magic[8];          //! magic bytes from dex, different values are possible
    int32_t checksum;          //! checksum to see if file is correct
    uint8_t signature[20];     //! signature of dex
    uint32_t file_size;        //! current file size
    uint32_t header_size;      //! size of this header
    uint32_t endian_tag;       //! type of endianess of the file
    uint32_t link_size;        //! data for statically linked files
    uint32_t link_off;         //!
    uint32_t map_off;          //!
    uint32_t string_ids_size;  //! number of DexStrings
    uint32_t string_ids_off;   //! offset of the DexStrings
    uint32_t type_ids_size;    //! number of DexTypes
    uint32_t type_ids_off;     //! offset of the DexTypes
    uint32_t proto_ids_size;   //! number of prototypes
    uint32_t proto_ids_off;    //! offset of the prototypes
    uint32_t field_ids_size;   //! number of fields
    uint32_t field_ids_off;    //! offset of the fields
    uint32_t method_ids_size;  //! number of methods
    uint32_t method_ids_off;   //! offset of the methods
    uint32_t class_defs_size;  //! number of class definitions
    uint32_t class_defs_off;   //! offset of the class definitions
    uint32_t data_size;        //! data area, containing all the support data for the tables listed above
    uint32_t data_off;         //!
} h_dex_header_t;
#pragma pack()

SHURIKENCOREAPI h_dex_header_t * get_dex_header(hDexParser parser);
SHURIKENCOREAPI size_t get_number_of_strings(hDexParser parser);
SHURIKENCOREAPI const char* get_string_by_id(hDexParser parser, size_t i);

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
    VOID
};

// Structure for the fundamental type
typedef struct hdvmfundamental_t {
    enum hfundamental_e fundamental;
    const char *name;
} hdvmfundamental_t;

// Structure for the class type
typedef struct hdvmclass_t {
    const char *class_name;
} hdvmclass_t;

// Structure for the array type
typedef struct hdvmarray_t {
    const char *array_name;
    size_t depth;
    struct hdvmtype_t *array_type;  // Note: Forward declaration
} hdvmarray_t;

// Structure for the high-level type
typedef struct hdvmtype_t {
    enum htype_e type;
    const char *raw_type;

    union {
        hdvmfundamental_t fundamental;
        hdvmclass_t class_type;
        hdvmarray_t array_type;
    };
} hdvmtype_t;


typedef struct hdvmmethod_t {

    /// @brief Class which method belongs to
    const char *belonging_class;
    /// @brief Prototype of the current method
    const char *protoId;
    /// @brief Name of the method
    const char *name;
    /// @brief Pretty name of the method with the prototype
    const char *pretty_name;

} hdvmmethod_t;


typedef struct {
    const char* class_name;
    const char* super_class;
    const char* source_file;
    uint16_t access_flags;
    uint32_t interfaces_off;
    uint32_t annotations_off;
    uint32_t class_data_off;
    uint32_t static_values_off;
    uint16_t static_fields_size;
    uint16_t instance_fields_size;
    uint16_t direct_methods_size;
    uint16_t virtual_methods_size;
    hdvmmethod_t **direct_methods;
} hdex_class_t;

SHURIKENCOREAPI size_t get_number_of_types(hDexParser parser);
SHURIKENCOREAPI hdvmtype_t* get_type_by_id(hDexParser parser, size_t i);
SHURIKENCOREAPI void destroy_type(hdvmtype_t *dvmtype);
SHURIKENCOREAPI size_t get_number_of_methods(hDexParser parser);
SHURIKENCOREAPI size_t get_number_of_classes(hDexParser parser);
SHURIKENCOREAPI hdvmmethod_t* get_methods_list(hDexParser parser);
SHURIKENCOREAPI hdex_class_t* get_classes(hDexParser parser);



 





};

#endif //SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
