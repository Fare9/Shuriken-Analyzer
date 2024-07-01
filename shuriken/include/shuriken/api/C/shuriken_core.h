//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file shuriken_parsers_core.h
// @brief Shim in C for accessing the different data from ShurikenLib

#ifndef SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
#define SHURIKENLIB_SHURIKEN_PARSERS_CORE_H

#ifdef __cplusplus
#if defined(_WIN32) || defined(__WIN32__)
#ifdef SHURIKENLIB_EXPORTS
#define SHURIKENCOREAPI __declspec(dllexport)
#else
#define SHURIKENCOREAPI __declspec(dllimport)
#endif
#else
#define SHURIKENCOREAPI extern "C"
#endif
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#else
#define SHURIKENCOREAPI
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#endif

extern "C" {

typedef void *hDexContext;

/// C - DEX part of the CORE API from ShurikenLib

///--------------------------- Parser API ---------------------------

/// @brief DexTypes of the DVM we have by default fundamental,
/// classes and array DexTypes
enum htype_e {
    FUNDAMENTAL,//! fundamental type (int, float...)
    CLASS,      //! user defined class
    ARRAY,      //! an array type
    UNKNOWN     //! maybe wrong?
};

/// @brief enum with the fundamental DexTypes
enum hfundamental_e {
    BOOLEAN,
    BYTE,
    CHAR,
    DOUBLE,
    FLOAT,
    INT,
    LONG,
    SHORT,
    VOID,
    FUNDAMENTAL_NONE = 99
};

/// @brief access flags from the Dalvik Virtual Machine
enum access_flags_e {
    ACCESS_FLAGS_NONE = 0x0,           //! No access flags
    ACC_PUBLIC = 0x1,                  //! public type
    ACC_PRIVATE = 0x2,                 //! private type
    ACC_PROTECTED = 0x4,               //! protected type
    ACC_STATIC = 0x8,                  //! static (global) type
    ACC_FINAL = 0x10,                  //! final type (constant)
    ACC_SYNCHRONIZED = 0x20,           //! synchronized
    ACC_VOLATILE = 0x40,               //! Java volatile
    ACC_BRIDGE = 0x40,                 //!
    ACC_TRANSIENT = 0x80,              //!
    ACC_VARARGS = 0x80,                //!
    ACC_NATIVE = 0x100,                //! native type
    ACC_INTERFACE = 0x200,             //! interface type
    ACC_ABSTRACT = 0x400,              //! abstract type
    ACC_STRICT = 0x800,                //!
    ACC_SYNTHETIC = 0x1000,            //!
    ACC_ANNOTATION = 0x2000,           //!
    ACC_ENUM = 0x4000,                 //! enum type
    UNUSED = 0x8000,                   //!
    ACC_CONSTRUCTOR = 0x10000,         //! constructor type
    ACC_DECLARED_SYNCHRONIZED = 0x20000//!
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
    const char *type_value;
    /// @brief access flags from the field
    uint16_t access_flags;
} hdvmfield_t;

/// @brief Structure which keeps information from a method
/// this can be accessed from the class data
typedef struct hdvmmethod_t_ {
    /// @brief name of the method
    const char *method_name;
    /// @brief prototype of the method
    const char *prototype;
    /// @brief access flags
    uint16_t access_flags;
    /// @brief number of registers
    uint32_t code_size;
    /// @brief pointer to a code buffer
    uint8_t *code;
    /// @brief Full Dalvik name
    const char *dalvik_name;
    /// @brief Demangled name
    const char *demangled_name;
} hdvmmethod_t;

/// @brief Structure representing the classes in the DEX file
typedef struct hdvmclass_t {
    /// @brief name of the class
    const char *class_name;
    /// @brief name of the super class
    const char *super_class;
    /// @brief name of the source file (if exists)
    const char *source_file;
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
SHURIKENCOREAPI hDexContext parse_dex(const char *filePath);

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
SHURIKENCOREAPI const char *get_string_by_id(hDexContext context, size_t i);

/// @brief Get the number of classes from the DEX file
/// @param context dex from where to retrieve the number of classes
/// @return number of classes
SHURIKENCOREAPI uint16_t get_number_of_classes(hDexContext context);

/// @brief Get a class structure given an ID
/// @param context DEX from where to retrieve the class
/// @param i id of the class to retrieve
/// @return class from the DEX file
SHURIKENCOREAPI hdvmclass_t *get_class_by_id(hDexContext context, uint16_t i);

/// @brief Get a class structure given a class name
/// @param context DEX from where to retrieve the class
/// @param class_name name of the class to retrieve
/// @return class from the DEX file
SHURIKENCOREAPI hdvmclass_t *get_class_by_name(hDexContext context, const char *class_name);

/// @brief Get a method structure given a full dalvik name.
/// @param context DEX from where to retrieve the method
/// @param method_name LclassName;->methodName(parameters)RetType
/// @return pointer to hdvmmethod_t, null if the method does not exist
SHURIKENCOREAPI hdvmmethod_t *get_method_by_name(hDexContext context, const char *method_name);


///--------------------------- Disassembler API ---------------------------

/// @brief Instruction types from the Dalvik Virtual Machine
enum dexinsttype_e {
    DEX_INSTRUCTION00X,
    DEX_INSTRUCTION10X,
    DEX_INSTRUCTION12X,
    DEX_INSTRUCTION11N,
    DEX_INSTRUCTION11X,
    DEX_INSTRUCTION10T,
    DEX_INSTRUCTION20T,
    DEX_INSTRUCTION20BC,
    DEX_INSTRUCTION22X,
    DEX_INSTRUCTION21T,
    DEX_INSTRUCTION21S,
    DEX_INSTRUCTION21H,
    DEX_INSTRUCTION21C,
    DEX_INSTRUCTION23X,
    DEX_INSTRUCTION22B,
    DEX_INSTRUCTION22T,
    DEX_INSTRUCTION22S,
    DEX_INSTRUCTION22C,
    DEX_INSTRUCTION22CS,
    DEX_INSTRUCTION30T,
    DEX_INSTRUCTION32X,
    DEX_INSTRUCTION31I,
    DEX_INSTRUCTION31T,
    DEX_INSTRUCTION31C,
    DEX_INSTRUCTION35C,
    DEX_INSTRUCTION3RC,
    DEX_INSTRUCTION45CC,
    DEX_INSTRUCTION4RCC,
    DEX_INSTRUCTION51L,
    DEX_PACKEDSWITCH,
    DEX_SPARSESWITCH,
    DEX_FILLARRAYDATA,
    DEX_DALVIKINCORRECT,
    DEX_NONE_OP = 99,
};

/// @brief Structure for an instruction in the dalvik virtual machine
typedef struct hdvminstruction_t_ {
    /// @brief Instruction type enum
    dexinsttype_e instruction_type;
    /// @brief length of the instruction
    uint32_t instruction_length;
    /// @brief idx of the instruction
    uint64_t address;
    /// @brief opcode of the instruction
    uint32_t op;
    /// @brief Disassembly of the instruction
    const char *disassembly;
} hdvminstruction_t;

/// @brief Structure that keeps information about a handler
typedef struct dvmhandler_data_t_ {
    /// @brief type of handled exception
    const char *handler_type;
    /// @brief start address of the handler
    uint64_t handler_start_addr;
} dvmhandler_data_t;

/// @brief Structure with the information from the exceptions
/// in the code
typedef struct dvmexceptions_data_t_ {
    /// @brief start address from the try
    uint64_t try_value_start_addr;
    /// @brief last address from the try
    uint64_t try_value_end_addr;
    /// @brief number of handlers associated with the try
    size_t n_of_handlers;
    /// @brief pointer to an array of dvmhandler_data_t
    dvmhandler_data_t *handler;
} dvmexceptions_data_t;

/// @brief Structure that represents a disassembled method from
/// the dalvik file
typedef struct dvmdisassembled_method_t_ {
    /// @brief pointer to the method
    hdvmmethod_t *method_id;
    /// @brief number of registers
    uint16_t n_of_registers;
    /// @brief number of exception information structures
    size_t n_of_exceptions;
    /// @brief all the exceptions from the method
    dvmexceptions_data_t *exception_information;
    /// @brief number of instructions from the method
    size_t n_of_instructions;
    /// @brief array of all the instructions from the method
    hdvminstruction_t *instructions;
    /// @brief Full disassembled method
    const char *method_string;
} dvmdisassembled_method_t;

/// @brief Disassemble a DEX file and generate an internal DexDisassembler
/// @param context DEX to disassemble the methods
SHURIKENCOREAPI void disassemble_dex(hDexContext context);

/// @brief Get a method structure given a full dalvik name.
/// @param context DEX from where to retrieve the method
/// @param method_name LclassName;->methodName(parameters)RetType
/// @return pointer to a disassembled method
SHURIKENCOREAPI dvmdisassembled_method_t *get_disassembled_method(hDexContext context, const char *method_name);

///--------------------------- Analysis API ---------------------------
typedef struct hdvmclassanalysis_t_ hdvmclassanalysis_t;

typedef struct hdvmmethodanalysis_t_ hdvmmethodanalysis_t;

typedef struct hdvmfieldanalysis_t_ hdvmfieldanalysis_t;

/// @brief Xref that contains class, method and instruction address
typedef struct hdvm_class_method_idx_t_ {
    /// @brief class of the xref
    hdvmclassanalysis_t * cls;
    /// @brief method of the xref
    hdvmmethodanalysis_t * method;
    /// @brief idx
    int64_t idx;
} hdvm_class_method_idx_t;

/// @brief Xref that contains class, field and instruction address
typedef struct hdvm_class_field_idx_t_ {
    /// @brief class of the xref
    hdvmclassanalysis_t * cls;
    /// @brief field of the xref
    hdvmfieldanalysis_t * field;
    /// @brief idx
    int64_t idx;
} hdvm_class_field_idx_t;

/// @brief Xref that contains class and instruction address
typedef struct hdvm_class_idx_t_ {
    /// @brief class of the xref
    hdvmclassanalysis_t * cls;
    /// @brief idx
    int64_t idx;
};

/// @brief Structure that stores information of a basic block
typedef struct hdvmbasicblock_t_ {
    /// @brief Number of instructions in the block
    size_t n_of_instructions;
    /// @brief Pointer to the instructions in the block
    hdvminstruction_t *instructions;
    /// @brief Is it a try block?
    char try_block;
    /// @brief Is it a catch block
    char catch_block;
    /// @brief String value of the handler type
    const char *handler_type;
    /// @brief Name of the basic block
    const char *name;
    /// @brief Whole representation of a basic block in string format
    const char *block_string;
} hdvmbasicblock_t;

/// @brief Structure to keep all the basic blocks
typedef struct basic_blocks_t_ {
    /// @brief Number of basic blocks
    size_t n_of_blocks;
    /// @brief pointer to an array of basic blocks
    hdvmbasicblock_t * blocks;
} basic_blocks_t;

/// @brief FieldAnalysis structure
typedef struct hdvmfieldanalysis_t_ {
    /// @brief Full name of the FieldAnalysis
    const char *name;
    /// @brief Number of xrefread
    size_t n_of_xrefread;
    /// @brief xrefread
    hdvm_class_method_idx_t * xrefread;
    /// @brief Number of xrefwrite
    size_t n_of_xrefwrite;
    /// @brief xrefwrite
    hdvm_class_method_idx_t * xrefwrite;
} hdvmfieldanalysis_t;

typedef struct hdvmstringanalysis_t_ {
    /// @brief value of that string
    const char *value;
    /// @brief number of xreffrom
    size_t n_of_xreffrom;
    /// @brief xreffrom
    hdvm_class_method_idx_t * xreffrom;
} hdvmstringanalysis_t;

typedef struct hdvmmethodanalysis_t_ {
    /// @brief name of the method
    const char *name;
    /// @brief descriptor of the method
    const char *description;
    /// @brief access flags
    access_flags_e access_flags;
    /// @brief class name
    const char *class_name;
    /// @brief basic blocks
    basic_blocks_t basic_blocks;
    /// @brief 
} hdvmmethodanalysis_t;

};

#endif//SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
