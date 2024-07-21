##########################################################
# Shuriken-Analyzer: library for bytecode analysis.
# @author Farenain <kunai.static.analysis@gmail.com>
# @file dex.py
# @brief Structures from the Shuriken core API for DEX
##########################################################

import ctypes.util


# C enums
## htype_e
class htype_e(ctypes.c_int):
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

# C structures but in Python

# @brief Structure which keeps information from a field
# this can be accessed from the class data
class hdvmfield_t(ctypes.Structure):
    _fields_ = (
        ('name', ctypes.c_char_p),
        ('type', htype_e),
        ('fundamental_value', hfundamental_e),
        ('type_value', ctypes.c_char_p),
        ('access_flags', accessflags_e)
    )


# @brief Structure which keeps information from a method
# this can be accessed from the class data
class hdvmmethod_t(ctypes.Structure):
    _fields_ = (
        ('method_name', ctypes.c_char_p),
        ('prototype', ctypes.c_char_p),
        ('access_flags', accessflags_e),
        ('code_size', ctypes.c_uint32),
        ('code', ctypes.POINTER(ctypes.c_uint8)),
        ('dalvik_name', ctypes.c_char_p),
        ('demangled_name', ctypes.c_char_p)
    )


# @brief Structure representing the classes in the DEX file
class hdvmclass_t(ctypes.Structure):
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

# @brief Structure for an instruction in the dalvik virtual machine
class hdvminstruction_t(ctypes.Structure):
    _fields_ = [
        ("instruction_type", dexinsttype_e),
        ("instruction_length", ctypes.c_uint32),
        ("address", ctypes.c_uint64),
        ("op", ctypes.c_uint32),
        ("disassembly", ctypes.c_char_p)
    ]

# @brief Structure that keeps information about a handler
class dvmhandler_data_t(ctypes.Structure):
    _fields_ = [
        ("handler_type", ctypes.c_char_p),
        ("handler_start_addr", ctypes.c_uint64)
    ]

# @brief Structure with the information from the exceptions
# in the code
class dvmexceptions_data_t(ctypes.Structure):
    _fields_ = [
        ("try_value_start_addr", ctypes.c_uint64),
        ("try_value_end_addr", ctypes.c_uint64),
        ("n_of_handlers", ctypes.c_size_t),
        ("handler", ctypes.POINTER(dvmhandler_data_t))
    ]

# @brief Structure that represents a disassembled method from
# the dalvik file
class dvmdisassembled_method_t(ctypes.Structure):
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
    pass

class hdvmmethodanalysis_t(ctypes.Structure):
    pass

class hdvmfieldanalysis_t(ctypes.Structure):
    pass

# @brief Xref that contains class, method and instruction address
class hdvm_class_method_idx_t(ctypes.Structure):
    _fields_ = [
        ("cls", ctypes.POINTER(hdvmclassanalysis_t)),
        ("method", ctypes.POINTER(hdvmmethodanalysis_t)),
        ("idx", ctypes.c_int64)
    ]

# @brief Xref that contains class, field and instruction address
class hdvm_class_field_idx_t(ctypes.Structure):
    _fields_ = [
        ("cls", ctypes.POINTER(hdvmclassanalysis_t)),
        ("field", ctypes.POINTER(hdvmfieldanalysis_t)),
        ("idx", ctypes.c_int64)
    ]

# @brief Xref that contains class and instruction address
class hdvm_class_idx_t(ctypes.Structure):
    _fields_ = [
        ("cls", ctypes.POINTER(hdvmclassanalysis_t)),
        ("idx", ctypes.c_int64)
    ]

# @brief Structure that stores information of a basic block
class hdvmbasicblock_t(ctypes.Structure):
    _fields_ = [
        ("n_of_instructions", ctypes.c_size_t),
        ("instructions", ctypes.POINTER(hdvminstruction_t)),
        ("try_block", ctypes.c_char),
        ("catch_block", ctypes.c_char),
        ("handler_type", ctypes.c_char_p),
        ("name", ctypes.c_char_p),
        ("block_string", ctypes.c_char_p),
    ]

class basic_blocks_t(ctypes.Structure):
    _fields_ = [
        ("n_of_blocks", ctypes.c_size_t),
        ("block", ctypes.POINTER(hdvmbasicblock_t))
    ]

# @brief FieldAnalysis structure
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
        ("external", ctypes.c_char),
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

