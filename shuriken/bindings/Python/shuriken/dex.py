##########################################################
# Shuriken-Analyzer: library for bytecode analysis.
# @author Farenain <kunai.static.analysis@gmail.com>
# @file dex.py
# @brief Structures from the Shuriken core API for DEX
##########################################################

import ctypes.util


# C enums

class htype_e(ctypes.c_int):
    """
    DexTypes of the DVM we have by default fundamental,
    classes and array DexTypes.

    Fields:
    - FUNDAMENTAL: fundamental type (int, float...)
    - CLASS: user defined class
    - ARRAY: an array type
    - UNKNOWN: maybe wrong?
    """

    FUNDAMENTAL = 0
    CLASS = 1
    ARRAY = 2
    UNKNOWN = 3

    def __str__(self):
        value = self.value
        for attr_name in dir(self):
            flag_value = getattr(self, attr_name)
            if isinstance(flag_value, int) and flag_value == value:
                return attr_name
        return "UNKNOWN"


## hfundamental_e
class hfundamental_e(ctypes.c_int):
    """
    enum with the fundamental DexTypes
    """

    BOOLEAN = 0
    BYTE = 1
    CHAR = 2
    DOUBLE = 3
    FLOAT = 4
    INT = 5
    LONG = 6
    SHORT = 7
    VOID = 8
    FUNDAMENTAL_NONE = 99

    def __str__(self):
        value = self.value
        for attr_name in dir(self):
            flag_value = getattr(self, attr_name)
            if isinstance(flag_value, int) and flag_value == value:
                return attr_name
        return "NONE"


## accessflags_e
class accessflags_e(ctypes.c_uint16):
    """
    access flags from the Dalvik Virtual Machine

    Fields:
    - ACCESS_FLAGS_NONE: No access flags
    - ACC_PUBLIC: public type
    - ACC_PRIVATE: private type
    - ACC_PROTECTED: protected type
    - ACC_STATIC: static (global) type
    - ACC_FINAL: final type (constant)
    - ACC_SYNCHRONIZED: synchronized
    - ACC_VOLATILE: Java volatile
    - ACC_BRIDGE:
    - ACC_TRANSIENT:
    - ACC_VARARGS:
    - ACC_NATIVE: native type
    - ACC_INTERFACE: interface type
    - ACC_ABSTRACT: abstract type
    - ACC_STRICT:
    - ACC_SYNTHETIC:
    - ACC_ANNOTATION:
    - ACC_ENUM: enum type
    - UNUSED:
    - ACC_CONSTRUCTOR: constructor type
    - ACC_DECLARED_SYNCHRONIZED:
    """
    ACCESS_FLAGS_NONE = 0x0
    ACC_PUBLIC = 0x1
    ACC_PRIVATE = 0x2
    ACC_PROTECTED = 0x4
    ACC_STATIC = 0x8
    ACC_FINAL = 0x10
    ACC_SYNCHRONIZED = 0x20
    ACC_VOLATILE = 0x40
    ACC_BRIDGE = 0x40
    ACC_TRANSIENT = 0x80
    ACC_VARARGS = 0x80
    ACC_NATIVE = 0x100
    ACC_INTERFACE = 0x200
    ACC_ABSTRACT = 0x400
    ACC_STRICT = 0x800
    ACC_SYNTHETIC = 0x1000
    ACC_ANNOTATION = 0x2000
    ACC_ENUM = 0x4000
    UNUSED = 0x8000
    ACC_CONSTRUCTOR = 0x10000
    ACC_DECLARED_SYNCHRONIZED = 0x20000

    def __str__(self):
        flags = []
        value = self.value
        for attr_name in dir(self):
            if not attr_name.startswith("__") and not attr_name.startswith("ACC_"):
                continue
            flag_value = getattr(self, attr_name)
            if isinstance(flag_value, int) and flag_value & value:
                flags.append(attr_name)
        return '|'.join(flags)


## dexinsttype_e
class dexinsttype_e(ctypes.c_int):
    """
    Instruction types from the Dalvik Virtual Machine
    """
    
    DEX_INSTRUCTION00X = 0
    DEX_INSTRUCTION10X = 1
    DEX_INSTRUCTION12X = 2
    DEX_INSTRUCTION11N = 3
    DEX_INSTRUCTION11X = 4
    DEX_INSTRUCTION10T = 5
    DEX_INSTRUCTION20T = 6
    DEX_INSTRUCTION20BC = 7
    DEX_INSTRUCTION22X = 8
    DEX_INSTRUCTION21T = 9
    DEX_INSTRUCTION21S = 10
    DEX_INSTRUCTION21H = 11
    DEX_INSTRUCTION21C = 12
    DEX_INSTRUCTION23X = 13
    DEX_INSTRUCTION22B = 14
    DEX_INSTRUCTION22T = 15
    DEX_INSTRUCTION22S = 16
    DEX_INSTRUCTION22C = 17
    DEX_INSTRUCTION22CS = 18
    DEX_INSTRUCTION30T = 19
    DEX_INSTRUCTION32X = 20
    DEX_INSTRUCTION31I = 21
    DEX_INSTRUCTION31T = 22
    DEX_INSTRUCTION31C = 23
    DEX_INSTRUCTION35C = 24
    DEX_INSTRUCTION3RC = 25
    DEX_INSTRUCTION45CC = 26
    DEX_INSTRUCTION4RCC = 27
    DEX_INSTRUCTION51L = 28
    DEX_PACKEDSWITCH = 29
    DEX_SPARSESWITCH = 30
    DEX_FILLARRAYDATA = 31
    DEX_DALVIKINCORRECT = 32
    DEX_NONE_OP = 99

    def __str__(self):
        for name, value in vars(dexinsttype_e).items():
            if value == self.value:
                return name
        return str(self.value)


## ref_type
class dexref_type_e(ctypes.c_int):
    REF_NEW_INSTANCE = 0x22
    REF_CLASS_USAGE = 0x1c
    INVOKE_VIRTUAL = 0x6e
    INVOKE_SUPER = 0x6f
    INVOKE_DIRECT = 0x70
    INVOKE_STATIC = 0x71
    INVOKE_INTERFACE = 0x72
    INVOKE_VIRTUAL_RANGE = 0x74
    INVOKE_SUPER_RANGE = 0x75
    INVOKE_DIRECT_RANGE = 0x76
    INVOKE_STATIC_RANGE = 0x77
    INVOKE_INTERFACE_RANGE = 0x78

    def __str__(self):
        for name, value in vars(dexref_type_e).items():
            if value == self.value:
                return name
        return str(self.value)


# C structures but in Python

class hdvmfield_t(ctypes.Structure):
    """
    Structure which keeps information from a field
    this can be accessed from the class data.


    Fields:
    - class_name (type: c_char_p): Name of the class the field belong to
    - name (type: c_char_p): Name of the field
    - type (type: htype_e): Type of the field
    - fundamenta_value (type: hfundamental_e): In case `type` == FUNDAMENTAL in case of ARRAY if the base type is a fundamental value, it contains that value
    - type_value (type: c_char_p): String value of the type
    - access_flags (type: accessflags_e): access flags from the field
    """

    _fields_ = (
        ('class_name', ctypes.c_char_p),
        ('name', ctypes.c_char_p),
        ('type', htype_e),
        ('fundamental_value', hfundamental_e),
        ('type_value', ctypes.c_char_p),
        ('access_flags', accessflags_e)
    )


class hdvmmethod_t(ctypes.Structure):
    """
    Structure which keeps information from a method
    this can be accessed from the class data.

    Fields:
    - class_name (type: c_char_p): Name of the class the method belongs to
    - method_name (type: c_char_p): Name of the method
    - prototype (type: c_char_p): Prototype of the method
    - access_flags (type: accessflags_e): access flags from the method
    - code_size (type: c_uint32): number of bytes from the code
    - code (type: POINTER(c_uint8)): pointer to a code buffer
    - dalvik_name (type: c_char_p): Full Dalvik name
    - demangled_name (type: c_char_p): Demangled name
    """
    _fields_ = (
        ('class_name', ctypes.c_char_p),
        ('method_name', ctypes.c_char_p),
        ('prototype', ctypes.c_char_p),
        ('access_flags', accessflags_e),
        ('code_size', ctypes.c_uint32),
        ('code', ctypes.POINTER(ctypes.c_uint8)),
        ('dalvik_name', ctypes.c_char_p),
        ('demangled_name', ctypes.c_char_p)
    )


class hdvmclass_t(ctypes.Structure):
    """
    Structure representing the classes in the DEX file

    Fields:
    - class_name (type: c_char_p): Name of the class the class belongs to
    - super_class (type: c_char_p): Super class of the class
    - source_file (type: c_char_p): Source file of the class
    - access_flags (type: accessflags_e): access flags from the class
    - direct_methods_size (type: c_uint16): number of direct methods
    - direct_methods (type: POINTER(hdvmmethod_t): array of direct methods
    - virtual_methods_size (type: c_uint16): number of virtual methods
    - virtual_methods (type: POINTER(hdvmmethod_t): array of virtual methods
    - instance_fields_size (type: c_uint16): number of instance fields
    - instance_fields (type: POINTER(hdvmfield_t): instance fields
    - static_fields_size (type: c_uint16): number of static fields
    - static_fields (type: POINTER(hdvmfield_t): static fields
    """
    _fields_ = (
        ('class_name', ctypes.c_char_p),
        ('super_class', ctypes.c_char_p),
        ('source_file', ctypes.c_char_p),
        ('access_flags', accessflags_e),
        ('direct_methods_size', ctypes.c_uint16),
        ('direct_methods', ctypes.POINTER(hdvmmethod_t)),
        ('virtual_methods_size', ctypes.c_uint16),
        ('virtual_methods', ctypes.POINTER(hdvmmethod_t)),
        ('instance_fields_size', ctypes.c_uint16),
        ('instance_fields', ctypes.POINTER(hdvmfield_t)),
        ('static_fields_size', ctypes.c_uint16),
        ('static_fields', ctypes.POINTER(hdvmfield_t))
    )


class hdvminstruction_t(ctypes.Structure):
    """
    Structure for an instruction in the dalvik virtual machine

    Fields:
    - instruction_type (type: dexinsttype_e): Instruction type enum
    - instruction_length (type: c_uint32): length of the instruction
    - address (type: c_uint64): idx of the instruction
    - op (type: c_uint32): opcode of the instruction
    - disassembly (type: c_char_p): disassembly of the instruction
    """
    _fields_ = [
        ("instruction_type", dexinsttype_e),
        ("instruction_length", ctypes.c_uint32),
        ("address", ctypes.c_uint64),
        ("op", ctypes.c_uint32),
        ("disassembly", ctypes.c_char_p)
    ]


class dvmhandler_data_t(ctypes.Structure):
    """
    Structure that keeps information about a handler

    Fields:
    - handler_type (type: c_char_p): type of handled exception
    - handler_start_addr (type: c_uint64): start address of the handler
    """
    _fields_ = [
        ("handler_type", ctypes.c_char_p),
        ("handler_start_addr", ctypes.c_uint64)
    ]


class dvmexceptions_data_t(ctypes.Structure):
    """
    Structure with the information from the exceptions
    in the code

    Fields:
    - try_value_start_addr (type: c_uint64): start address of the try
    - try_value_end_addr (type: c_uint64): last address of the try
    - n_of_handlers (type: c_size_t): number of handlers associated with the try
    - handler (type: POINTER(dvmhandler_data_t)): pointer to an array of dvmhandler_data_t
    """
    _fields_ = [
        ("try_value_start_addr", ctypes.c_uint64),
        ("try_value_end_addr", ctypes.c_uint64),
        ("n_of_handlers", ctypes.c_size_t),
        ("handler", ctypes.POINTER(dvmhandler_data_t))
    ]


class dvmdisassembled_method_t(ctypes.Structure):
    """
    Structure that represents a disassembled method from
    the dalvik file

    Fields:
    - method_id (type: POINTER(hdvmmethod_t)): pointer to the method
    - n_of_registers (type: c_uint16): number of registers
    - n_of_exceptions (type: c_size_t): number of exception information structures
    - exception_information (type: POINTER(dvmexceptions_data_t)): all the exceptions from the method
    - n_of_instructions (type: c_size_t): number of instructions in the method
    - instructions (type: hdvminstruction_t): array of all the instructions in the method
    - method_string (type: c_char_p): full disassembled method
    """
    _fields_ = [
        ("method_id", ctypes.POINTER(hdvmmethod_t)),
        ("n_of_registers", ctypes.c_uint16),
        ("n_of_exceptions", ctypes.c_size_t),
        ("exception_information", ctypes.POINTER(dvmexceptions_data_t)),
        ("n_of_instructions", ctypes.c_size_t),
        ("instructions", ctypes.POINTER(hdvminstruction_t)),
        ("method_string", ctypes.c_char_p)
    ]


# Forward declarations (empty classes to act as placeholders)
# later we will declare the fields
class hdvmclassanalysis_t(ctypes.Structure):
    """
    Structure that represents a classanalysis

    Fields:
    - is_external (type: c_char_p): is external class?
    - extends_ (type: c_char_p): Name of the class it extends
    - name_ (type: c_char_p): Name of the class
    - n_of_methods (type: c_size_t): number of methods
    - methods (type: POINTER(POINTER(hdvmmethodanalysis_t))): pointer to an array of methods
    - n_of_fields (type: c_size_t): number of fields
    - fields (type: POINTER(POINTER(hdvmfieldanalysis_t))): pointer to an array of fields
    - n_of_xrefnewinstance (type: c_size_t): number of xrefnewinstance
    - xrefnewinstance (type: POINTER(hdvm_method_idx_t)): New instance of this class
    - n_of_xrefconstclass (type: c_size_t): number of xrefconstclass
    - xrefconstclass (type: POINTER(hdvm_method_idx_t)): use of const class of this class
    - n_of_xrefto (type: c_size_t): number of xrefto
    - xrefto (type: POINTER(hdvm_classxref_t)): Classes that this class calls
    - n_of_xreffrom (type: c_size_t): number of xreffrom
    - xreffrom (type: POINTER(hdvm_classxref_t)): Classes that call this class
    """
    pass

class hdvmmethodanalysis_t(ctypes.Structure):
    """
    Structure representing method analysis in HDVM.

    Fields:
    - name (type: c_char_p): Name of the method.
    - descriptor (type: c_char_p): Descriptor of the method.
    - full_name (type: c_char_p): Full name of the method, including class name and descriptor.
    - external (type: c_int): Flag indicating if the method is external or not.
    - access_flags (type: accessflags_e): Access flags of the method.
    - class_name (type: c_char_p): Name of the class to which the method belongs.
    - basic_blocks (type: POINTER(basic_blocks_t)): Pointer to the basic blocks of the method.
    - n_of_xrefread (type: c_size_t): Number of field reads in the method.
    - xrefread (type: POINTER(hdvm_class_field_idx_t)): Pointer to the xrefs of field reads.
    - n_of_xrefwrite (type: c_size_t): Number of field writes in the method.
    - xrefwrite (type: POINTER(hdvm_class_field_idx_t)): Pointer to the xrefs of field writes.
    - n_of_xrefto (type: c_size_t): Number of methods called by this method.
    - xrefto (type: POINTER(hdvm_class_method_idx_t)): Pointer to the methods called from this method.
    - n_of_xreffrom (type: c_size_t): Number of methods that call this method.
    - xreffrom (type: POINTER(hdvm_class_method_idx_t)): Pointer to the methods that call this method.
    - n_of_xrefnewinstance (type: c_size_t): Number of instances where this method is used to create new instances.
    - xrefnewinstance (type: POINTER(hdvm_class_idx_t)): Pointer to the new instances created by this method.
    - n_of_xrefconstclass (type: c_size_t): Number of instances where this method uses a const class.
    - xrefconstclass (type: POINTER(hdvm_class_idx_t)): Pointer to the const classes used by this method.
    - method_string (type: c_char_p): Cache of the method string.
    """
    pass


class hdvmfieldanalysis_t(ctypes.Structure):
    """
    Structure representing field analysis in HDVM.

    Fields:
    - name (type: c_char_p): Full name of the FieldAnalysis.
    - n_of_xrefread (type: c_size_t): Number of references where the field is read.
    - xrefread (type: POINTER(hdvm_class_method_idx_t)): Pointer to the methods where the field is read.
    - n_of_xrefwrite (type: c_size_t): Number of references where the field is written to.
    - xrefwrite (type: POINTER(hdvm_class_method_idx_t)): Pointer to the methods where the field is written to.
    """
    pass


class hdvm_class_method_idx_t(ctypes.Structure):
    """
    Xref structure that contains class, method, and instruction address.

    Fields:
    - cls (type: POINTER(hdvmclassanalysis_t)): Pointer to the class of the xref.
    - method (type: POINTER(hdvmmethodanalysis_t)): Pointer to the method of the xref.
    - idx (type: c_int64): Instruction address or index.
    """
    _fields_ = [
        ("cls", ctypes.POINTER(hdvmclassanalysis_t)),
        ("method", ctypes.POINTER(hdvmmethodanalysis_t)),
        ("idx", ctypes.c_int64)
    ]


class hdvm_class_field_idx_t(ctypes.Structure):
    """
    Xref structure that contains class, field, and instruction address.

    Fields:
    - cls (type: POINTER(hdvmclassanalysis_t)): Pointer to the class of the xref.
    - field (type: POINTER(hdvmfieldanalysis_t)): Pointer to the field of the xref.
    - idx (type: c_int64): Instruction address or index.
    """
    _fields_ = [
        ("cls", ctypes.POINTER(hdvmclassanalysis_t)),
        ("field", ctypes.POINTER(hdvmfieldanalysis_t)),
        ("idx", ctypes.c_int64)
    ]


class hdvm_method_idx_t(ctypes.Structure):
    """
    Xref that contains a method and instruction address

    Fields:
    - method (type: POINTER(hdvmmethodanalysis_t)): Pointer to the method of the xref.
    - idx (type: c_int64): Instruction address or index.
    """
    _fields_ = [
        ("method", ctypes.POINTER(hdvmmethodanalysis_t)),
        ("idx", ctypes.c_int64)
    ]


class hdvm_class_idx_t(ctypes.Structure):
    '''
    Xref that contains class and instruction address

    Fields:
    - cls (type: POINTER(hdvmclassanalysis_t)): class of the xref
    - idx (type: c_int64): Instruction address
    '''
    _fields_ = [
        ("cls", ctypes.POINTER(hdvmclassanalysis_t)),
        ("idx", ctypes.c_int64)
    ]


class hdvm_reftype_method_idx_t(ctypes.Structure):
    """
    Structure that contains a type of reference, a method analysis where reference is
    and the idx in the method where the reference to a class is

    Fields:
    - refType (type: dexref_type_e): type of the reference
    - methodAnalysis (type: POINTER(hdvmmethodanalysis_t)): Pointer to the method of the xref
    - idx (type: c_uint64): Index of the reference
    """
    _fields_ = [
        ("refType", dexref_type_e),
        ("methodAnalysis", ctypes.POINTER(hdvmmethodanalysis_t)),
        ("idx", ctypes.c_uint64)
    ]


class hdvm_classxref_t(ctypes.Structure):
    """
    Reference of classes-methods and reference type.

    Fields:
    - classAnalysis (type: POINTER(hdvmclassanalysis_t)): pointer to a class analysis with the class of the xref
    - n_of_reftype_method_idx (type: c_size_t): number of references of type `hdvm_reftype_method_idx_t`
    - hdvmReftypeMethodIdx (type: POINTER(hdvm_reftype_method_idx_t)): array of `hdvm_reftype_method_idx_t` references
    """
    _fields_ = [
        ("classAnalysis", ctypes.POINTER(hdvmclassanalysis_t)),
        ("n_of_reftype_method_idx", ctypes.c_size_t),
        ("hdvmReftypeMethodIdx", ctypes.POINTER(hdvm_reftype_method_idx_t))
    ]


class hdvmbasicblock_t(ctypes.Structure):
    """
    Structure that stores information of a basic block.

    Fields:
    - n_of_instructions (type: c_size_t): Number of instructions in the block.
    - instructions (type: POINTER(hdvminstruction_t)): Pointer to the instructions in the block.
    - try_block (type: c_int): Flag indicating if this block is a try block.
    - catch_block (type: c_int): Flag indicating if this block is a catch block.
    - handler_type (type: c_char_p): String representing the handler type.
    - name (type: c_char_p): Name of the basic block.
    - block_string (type: c_char_p): String representation of the entire basic block.
    """
    _fields_ = [
        ("n_of_instructions", ctypes.c_size_t),
        ("instructions", ctypes.POINTER(hdvminstruction_t)),
        ("try_block", ctypes.c_int),
        ("catch_block", ctypes.c_int),
        ("handler_type", ctypes.c_char_p),
        ("name", ctypes.c_char_p),
        ("block_string", ctypes.c_char_p),
    ]


class basic_blocks_t(ctypes.Structure):
    '''
    Structure that stores all the basic blocks
    from a method.

    Fields:
    - n_of_blocks (type: c_size_t): number of blocks in the method
    - block (type: POINTER(hdvmbasicblock_t)): Pointer to the basic blocks.
    '''
    _fields_ = [
        ("n_of_blocks", ctypes.c_size_t),
        ("blocks", ctypes.POINTER(hdvmbasicblock_t))
    ]


hdvmfieldanalysis_t._fields_ = [
    ("name", ctypes.c_char_p),
    ("n_of_xrefread", ctypes.c_size_t),
    ("xrefread", ctypes.POINTER(hdvm_class_method_idx_t)),
    ("n_of_xrefwrite", ctypes.c_size_t),
    ("xrefwrite", ctypes.POINTER(hdvm_class_method_idx_t)),
]

hdvmmethodanalysis_t._fields_ = [
    ("name", ctypes.c_char_p),
    ("descriptor", ctypes.c_char_p),
    ("full_name", ctypes.c_char_p),
    ("external", ctypes.c_int),
    ("is_android_api", ctypes.c_int),
    ("access_flags", accessflags_e),
    ("class_name", ctypes.c_char_p),
    ("basic_blocks", ctypes.POINTER(basic_blocks_t)),
    ("n_of_xrefread", ctypes.c_size_t),
    ("xrefread", ctypes.POINTER(hdvm_class_field_idx_t)),
    ("n_of_xrefwrite", ctypes.c_size_t),
    ("xrefwrite", ctypes.POINTER(hdvm_class_field_idx_t)),
    ("n_of_xrefto", ctypes.c_size_t),
    ("xrefto", ctypes.POINTER(hdvm_class_method_idx_t)),
    ("n_of_xreffrom", ctypes.c_size_t),
    ("xreffrom", ctypes.POINTER(hdvm_class_method_idx_t)),
    ("n_of_xrefnewinstance", ctypes.c_size_t),
    ("xrefnewinstance", ctypes.POINTER(hdvm_class_idx_t)),
    ("n_of_xrefconstclass", ctypes.c_size_t),
    ("xrefconstclass", ctypes.POINTER(hdvm_class_idx_t)),
    ("method_string", ctypes.c_char_p),
]

hdvmclassanalysis_t._fields_ = [
    ("is_external", ctypes.c_int),
    ("extends_", ctypes.c_char_p),
    ("name_", ctypes.c_char_p),
    ("n_of_methods", ctypes.c_size_t),
    ("methods", ctypes.POINTER(ctypes.POINTER(hdvmmethodanalysis_t))),
    ("n_of_fields", ctypes.c_size_t),
    ("fields", ctypes.POINTER(ctypes.POINTER(hdvmfieldanalysis_t))),
    ("n_of_xrefnewinstance", ctypes.c_size_t),
    ("xrefnewinstance", ctypes.POINTER(hdvm_method_idx_t)),
    ("n_of_xrefconstclass", ctypes.c_size_t),
    ("xrefconstclass", ctypes.POINTER(hdvm_method_idx_t)),
    ("n_of_xrefto", ctypes.c_size_t),
    ("xrefto", ctypes.POINTER(hdvm_classxref_t)),
    ("n_of_xreffrom", ctypes.c_size_t),
    ("xreffrom", ctypes.POINTER(hdvm_classxref_t)),
]
