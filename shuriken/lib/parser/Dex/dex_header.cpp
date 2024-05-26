//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file header.cpp

#include "shuriken/parser/Dex/dex_header.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

#define ERROR_MESSAGE(field) "Error '" #field "' > 'file size'"

DexHeader::DexHeader(DexHeader &header) {
    memcpy(&dexheader, &header.dexheader, sizeof(dexheader_t));
}

void DexHeader::parse_header(common::ShurikenStream &stream) {
    auto my_logger = shuriken::logger();

    my_logger->info("Start parsing header");

    auto f_size = stream.get_file_size();

    // read the dex headerHeader
    stream.read_data<dexheader_t>(dexheader, sizeof(dexheader_t));

    if (dexheader.link_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(link_off));

    if (dexheader.map_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(map_off));

    if (dexheader.string_ids_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(string_ids_off));

    if (dexheader.type_ids_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(type_ids_off));

    if (dexheader.proto_ids_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(proto_ids_off));

    if (dexheader.method_ids_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(method_ids_off));

    if (dexheader.class_defs_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(class_defs_off));

    if (dexheader.data_off > f_size)
        throw std::runtime_error(ERROR_MESSAGE(data_off));

    my_logger->info("Finished parsing header");
}

void DexHeader::to_xml(std::ofstream &fos) {
    size_t i;

    fos << std::hex;
    fos << "<header>\n";
    fos << "\t<magic>";
    for (i = 0; i < 8; ++i)
        fos << dexheader.magic[i] << " ";
    fos << "</magic>\n";
    fos << "\t<checksum>" << dexheader.checksum << "</checksum>\n";
    fos << "\t<signature>";
    for (i = 0; i < 20; i++)
        fos << dexheader.signature[i] << " ";
    fos << "</signature>\n";
    fos << "\t<file_size>" << dexheader.file_size << "</file_size>\n";
    fos << "\t<header_size>" << dexheader.header_size << "</header_size>\n";
    fos << "\t<endian_tag>" << dexheader.endian_tag << "</endian_tag>\n";
    fos << "\t<link_size>" << dexheader.link_size << "</link_size>\n";
    fos << "\t<link_offset>" << dexheader.link_off << "</link_offset>\n";
    fos << "\t<map_offset>" << dexheader.map_off << "</map_offset>\n";
    fos << "\t<string_ids_size>" << dexheader.string_ids_size << "</string_ids_size>\n";
    fos << "\t<string_ids_offset>" << dexheader.string_ids_off << "</string_ids_offset>\n";
    fos << "\t<type_ids_size>" << dexheader.type_ids_size << "</type_ids_size>\n";
    fos << "\t<type_ids_offset>" << dexheader.type_ids_off << "</type_ids_offset>\n";
    fos << "\t<proto_ids_size>" << dexheader.proto_ids_size << "</proto_ids_size>\n";
    fos << "\t<proto_ids_offset>" << dexheader.proto_ids_off << "</proto_ids_offset>\n";
    fos << "\t<field_ids_size>" << dexheader.field_ids_size << "</field_ids_size>\n";
    fos << "\t<field_ids_offset>" << dexheader.field_ids_off << "</field_ids_offset>\n";
    fos << "\t<method_ids_size>" << dexheader.method_ids_size << "</method_ids_size>\n";
    fos << "\t<<method_ids_offset>" << dexheader.method_ids_off << "</method_ids_offset>\n";
    fos << "\t<class_defs_size>" << dexheader.class_defs_size << "</class_defs_size>\n";
    fos << "\t<class_defs_offset>" << dexheader.class_defs_off << "</class_defs_offset>\n";
    fos << "\t<data_size>" << dexheader.data_size << "</data_size>\n";
    fos << "\t<data_offset>" << dexheader.data_off << "</data_offset>\n";
}

void DexHeader::dump(std::ofstream &fos) {
    fos.seekp(0, std::ofstream::beg);
    fos.write(reinterpret_cast<const char *>(&dexheader), sizeof(dexheader_t));
}

const DexHeader::dexheader_t &DexHeader::get_dex_header_const() const {
    return dexheader;
}

DexHeader::dexheader_t &DexHeader::get_dex_header() {
    return dexheader;
}

std::uint64_t DexHeader::get_dex_header_size() const {
    return sizeof(dexheader_t);
}