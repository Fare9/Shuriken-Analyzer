//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file header.h
// @brief DexHeader of a DEX file represented by a structure

#ifndef SHURIKENLIB_DEX_HEADER_H
#define SHURIKENLIB_DEX_HEADER_H

#include "shuriken/common/shurikenstream.h"
#include <cstring>
#include <iostream>

namespace shuriken::parser::dex {
    class DexHeader {
    public:
#pragma pack(1)
        /// @brief Structure with the definition of the DEX header
        /// all these values are later used for parsing the other
        /// headers from DEX
        struct dexheader_t {
            std::uint8_t magic[8];        //! magic bytes from dex, different values are possible
            std::int32_t checksum;        //! checksum to see if file is correct
            std::uint8_t signature[20];   //! signature of dex
            std::uint32_t file_size;      //! current file size
            std::uint32_t header_size;    //! size of this header
            std::uint32_t endian_tag;     //! type of endianess of the file
            std::uint32_t link_size;      //! data for statically linked files
            std::uint32_t link_off;       //!
            std::uint32_t map_off;        //!
            std::uint32_t string_ids_size;//! number of DexStrings
            std::uint32_t string_ids_off; //! offset of the DexStrings
            std::uint32_t type_ids_size;  //! number of DexTypes
            std::uint32_t type_ids_off;   //! offset of the DexTypes
            std::uint32_t proto_ids_size; //! number of prototypes
            std::uint32_t proto_ids_off;  //! offset of the prototypes
            std::uint32_t field_ids_size; //! number of fields
            std::uint32_t field_ids_off;  //! offset of the fields
            std::uint32_t method_ids_size;//! number of methods
            std::uint32_t method_ids_off; //! offset of the methods
            std::uint32_t class_defs_size;//! number of class definitions
            std::uint32_t class_defs_off; //! offset of the class definitions
            std::uint32_t data_size;      //! data area, containing all the support data for the tables listed above
            std::uint32_t data_off;       //!
        };
#pragma pack()
    private:
        /// @brief struct with all the headers from the dex
        struct dexheader_t dexheader;

    public:
        /// @brief Constructor for the header, default one
        DexHeader() = default;

        /// @brief Destructor for the header, default one
        ~DexHeader() = default;

        /// @brief Copy constructor for DexHeader
        DexHeader(DexHeader &header);

        /// @brief Parse the header from a ShurikenStream file
        /// @param stream ShurikenStream where to read the header.
        void parse_header(common::ShurikenStream &stream);

        /// @brief Dump the content of the header to a file in XML format
        /// @param fos XML file where to write the content
        void to_xml(std::ofstream &fos);

        /// @brief Dump a binary format of the header
        /// @param fos file where to dump the binary header
        void dump(std::ofstream &fos);

        /// @brief Obtain a constant reference of the dex header struct
        /// if no value will be modified, use this function.
        /// @return const reference to header structure
        const dexheader_t &get_dex_header_const() const;

        /// @brief Obtain a reference of the dex header struct
        /// just in case in the future DEX modification is allowed
        /// @return reference to header structure
        dexheader_t &get_dex_header();

        /// @brief Obtain the size of the dex header structure
        /// @return
        std::uint64_t get_dex_header_size() const;
    };
}// namespace shuriken::parser::dex

#endif//SHURIKENLIB_DEX_HEADER_H
