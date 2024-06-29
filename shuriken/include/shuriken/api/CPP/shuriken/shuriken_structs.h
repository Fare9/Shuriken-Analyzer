#ifndef SHURIKEN_CPP_CORE_STRUCTS_H
#define SHURIKEN_CPP_CORE_STRUCTS_H

#include <cstdint>
#include <span>
namespace shurikenapi {

    enum class FundamentalValue { kBoolean, kByte, kChar, kDouble, kFloat, kInt, kLong, kShort, kVoid, kNone = 99 };
    enum class DexType { kFundamental, kClass, kArray, kUnknown };

#pragma pack(1)
    struct DexHeader {
        uint8_t magic[8];              //! magic bytes from dex, different values are possible
        std::int32_t checksum;         //! checksum to see if file is correct
        std::uint8_t signature[20];    //! signature of dex
        std::uint32_t file_size;       //! current file size
        std::uint32_t header_size;     //! size of this header
        std::uint32_t endian_tag;      //! type of endianess of the file
        std::uint32_t link_size;       //! data for statically linked files
        std::uint32_t link_off;        //!
        std::uint32_t map_off;         //!
        std::uint32_t string_ids_size; //! number of DexStrings
        std::uint32_t string_ids_off;  //! offset of the DexStrings
        std::uint32_t type_ids_size;   //! number of DexTypes
        std::uint32_t type_ids_off;    //! offset of the DexTypes
        std::uint32_t proto_ids_size;  //! number of prototypes
        std::uint32_t proto_ids_off;   //! offset of the prototypes
        std::uint32_t field_ids_size;  //! number of fields
        std::uint32_t field_ids_off;   //! offset of the fields
        std::uint32_t method_ids_size; //! number of methods
        std::uint32_t method_ids_off;  //! offset of the methods
        std::uint32_t class_defs_size; //! number of class definitions
        std::uint32_t class_defs_off;  //! offset of the class definitions
        std::uint32_t data_size;       //! data area, containing all the support data for the tables listed above
        std::uint32_t data_off;        //!
    };

    enum AccessFlags {
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

#pragma pack()

} // namespace shurikenapi
#endif // SHURIKEN_CPP_CORE_STRUCTS_H