//
// Created by fare9 on 6/08/24.
//

#ifndef SHURIKENPROJECT_SHURIKEN_CORE_DATA_H
#define SHURIKENPROJECT_SHURIKEN_CORE_DATA_H

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

/// @brief opaque pointers user will use for calling the different methods
typedef void *hDexContext;

typedef void *hApkContext;

///--------------------------- Parser Data ---------------------------

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
    /// @brief Name of the class the field belong to
    const char *class_name;
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
    /// @brief Name of the class the method belongs to
    const char *class_name;
    /// @brief name of the method
    const char *method_name;
    /// @brief prototype of the method
    const char *prototype;
    /// @brief access flags
    uint16_t access_flags;
    /// @brief number of bytes from the code
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

///--------------------------- Disassembler Data ---------------------------

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
    /// @brief start address of the try
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
    /// @brief number of instructions in the method
    size_t n_of_instructions;
    /// @brief array of all the instructions in the method
    hdvminstruction_t *instructions;
    /// @brief Full disassembled method
    const char *method_string;
} dvmdisassembled_method_t;

///--------------------------- Analysis Data ---------------------------

enum ref_type {
    REF_NEW_INSTANCE = 0x22,// new instance of a class
    REF_CLASS_USAGE = 0x1c, // class is used somewhere
    INVOKE_VIRTUAL = 0x6e,  // call of a method from a class
    INVOKE_SUPER = 0x6f,    // call of constructor of super class
    INVOKE_DIRECT = 0x70,   // call a method from a class
    INVOKE_STATIC = 0x71,   // call a static method from a class
    INVOKE_INTERFACE = 0x72,// call an interface method
    // same with ranges
    INVOKE_VIRTUAL_RANGE = 0x74,
    INVOKE_SUPER_RANGE = 0x75,
    INVOKE_DIRECT_RANGE = 0x76,
    INVOKE_STATIC_RANGE = 0x77,
    INVOKE_INTERFACE_RANGE = 0x78
};

typedef struct hdvmclassanalysis_t_ hdvmclassanalysis_t;

typedef struct hdvmmethodanalysis_t_ hdvmmethodanalysis_t;

typedef struct hdvmfieldanalysis_t_ hdvmfieldanalysis_t;

/// @brief Xref that contains class, method and instruction address
typedef struct hdvm_class_method_idx_t_ {
    /// @brief class of the xref
    hdvmclassanalysis_t *cls;
    /// @brief method of the xref
    hdvmmethodanalysis_t *method;
    /// @brief idx
    int64_t idx;
} hdvm_class_method_idx_t;

/// @brief xref that contains a method and instruction address
typedef struct hdvm_method_idx_t_ {
    hdvmmethodanalysis_t *method;
    int64_t idx;
} hdvm_method_idx_t;


/// @brief Xref that contains class, field and instruction address
typedef struct hdvm_class_field_idx_t_ {
    /// @brief class of the xref
    hdvmclassanalysis_t *cls;
    /// @brief field of the xref
    hdvmfieldanalysis_t *field;
    /// @brief idx
    int64_t idx;
} hdvm_class_field_idx_t;

/// @brief Xref that contains class and instruction address
typedef struct hdvm_class_idx_t_ {
    /// @brief class of the xref
    hdvmclassanalysis_t *cls;
    /// @brief idx
    int64_t idx;
} hdvm_class_idx_t;

/// @brief Structure that contains a type of reference, a method analysis where reference is
/// and the idx in the method where the reference to a class is
typedef struct hdvm_reftype_method_idx_t_ {
    ref_type reType;
    hdvmmethodanalysis_t *methodAnalysis;
    uint64_t idx;
} hdvm_reftype_method_idx_t;

typedef struct hdvm_classxref_t_ {
    hdvmclassanalysis_t *classAnalysis;
    size_t n_of_reftype_method_idx;
    hdvm_reftype_method_idx_t *hdvmReftypeMethodIdx;
} hdvm_classxref_t;


/// @brief Structure that stores information of a basic block
typedef struct hdvmbasicblock_t_ {
    /// @brief Number of instructions in the block
    size_t n_of_instructions;
    /// @brief Pointer to the instructions in the block
    hdvminstruction_t *instructions;
    /// @brief Is it a try block?
    int try_block;
    /// @brief Is it a catch block
    int catch_block;
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
    hdvmbasicblock_t *blocks;
} basic_blocks_t;

/// @brief FieldAnalysis structure
typedef struct hdvmfieldanalysis_t_ {
    /// @brief Full name of the FieldAnalysis
    const char *name;
    /// @brief Number of xrefread
    size_t n_of_xrefread;
    /// @brief xrefread
    hdvm_class_method_idx_t *xrefread;
    /// @brief Number of xrefwrite
    size_t n_of_xrefwrite;
    /// @brief xrefwrite
    hdvm_class_method_idx_t *xrefwrite;
} hdvmfieldanalysis_t;

/// @brief Structure to keep information about the string analysis
/// [UNUSED FOR NOW]
typedef struct hdvmstringanalysis_t_ {
    /// @brief value of that string
    const char *value;
    /// @brief number of xreffrom
    size_t n_of_xreffrom;
    /// @brief xreffrom
    hdvm_class_method_idx_t *xreffrom;
} hdvmstringanalysis_t;

/// @brief Structure to keep information about the method analysis
typedef struct hdvmmethodanalysis_t_ {
    /// @brief name of the method
    const char *name;
    /// @brief descriptor of the method
    const char *descriptor;
    /// @brief full name of the method including class name and descriptor
    const char *full_name;
    /// @brief flag indicating if the method is external or not
    int external;
    /// @brief flag indicating if the method is an android API
    int is_android_api;
    /// @brief access flags
    access_flags_e access_flags;
    /// @brief class name
    const char *class_name;
    /// @brief basic blocks
    basic_blocks_t *basic_blocks;
    /// @brief number of field read in method
    size_t n_of_xrefread;
    /// @brief xrefs of field read
    hdvm_class_field_idx_t *xrefread;
    /// @brief number of field write
    size_t n_of_xrefwrite;
    /// @brief xrefs of field write
    hdvm_class_field_idx_t *xrefwrite;
    /// @brief number of xrefto
    size_t n_of_xrefto;
    /// @brief methods called from the current method
    hdvm_class_method_idx_t *xrefto;
    /// @brief number of xreffrom
    size_t n_of_xreffrom;
    /// @brief methods that call the current method
    hdvm_class_method_idx_t *xreffrom;
    /// @brief Number of xrefnewinstance
    size_t n_of_xrefnewinstance;
    /// @brief new instance of the method
    hdvm_class_idx_t *xrefnewinstance;
    /// @brief Number of xrefconstclass
    size_t n_of_xrefconstclass;
    /// @brief use of const class
    hdvm_class_idx_t *xrefconstclass;
    /// @brief cache of method string
    const char *method_string;
} hdvmmethodanalysis_t;

/// @brief Structure to keep information about the class analysis
typedef struct hdvmclassanalysis_t_ {
    /// @brief is external class?
    int is_external;
    /// @brief Name of the class it extends
    const char *extends_;
    /// @brief name of the class
    const char *name_;
    /// @brief number of methods
    size_t n_of_methods;
    /// @brief pointer to an array of methods
    hdvmmethodanalysis_t **methods;
    /// @brief number of fields
    size_t n_of_fields;
    /// @brief pointer to an array of fields
    hdvmfieldanalysis_t **fields;
    /// @brief number of xrefnewinstance
    size_t n_of_xrefnewinstance;
    /// @brief New instance of this class
    hdvm_method_idx_t *xrefnewinstance;
    /// @brief number of const class
    size_t n_of_xrefconstclass;
    /// @brief use of const class of this class
    hdvm_method_idx_t *xrefconstclass;
    /// @brief number of xrefto
    size_t n_of_xrefto;
    /// @brief Classes that this class calls
    hdvm_classxref_t *xrefto;
    /// @brief number of xreffrom
    size_t n_of_xreffrom;
    /// @brief Classes that call this class
    hdvm_classxref_t *xreffrom;
} hdvmclassanalysis_t;
}

#endif//SHURIKENPROJECT_SHURIKEN_CORE_DATA_H
