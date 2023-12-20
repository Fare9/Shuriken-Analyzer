//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file java.cpp

#include "shuriken/parser/Dex/parser.h"

#include "shuriken/parser/Dex/dvm_types.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

void Parser::parse_dex(common::ShurikenStream& stream) {
    std::uint8_t magic[4];
    auto my_logger = shuriken::logger();
    my_logger->info("Start parsing dex file");

    if (stream.get_file_size() < sizeof(Header::dexheader_t))
        throw std::runtime_error("Error file provided to java has an incorrect size");

    stream.read_data<std::uint8_t[4]>(magic, sizeof(std::uint8_t[4]));

    if (memcmp(magic, shuriken::dex::dex_magic, sizeof(std::uint8_t[4])))
        throw std::runtime_error("Error file is not a dex file");

    // move to the beginning
    stream.seekg(0, std::ios_base::beg);

    // parsing of header
    header_.parse_header(stream);

    const auto & dex_header = header_.get_dex_header_const();

    // parsing of the rest of the fields
    strings_.parse_strings(stream,
                           dex_header.string_ids_off,
                           dex_header.string_ids_size);
    types_.parse_types(stream,
                       strings_,
                       dex_header.type_ids_off,
                       dex_header.type_ids_size);
    protos_.parse_protos(stream,
                         dex_header.proto_ids_size,
                         dex_header.proto_ids_off,
                         strings_,
                         types_);

    my_logger->info("Finished parsing dex file");
}