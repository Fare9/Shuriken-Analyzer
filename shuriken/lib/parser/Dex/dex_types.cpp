//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file DexTypes.cpp

#include "shuriken/parser/Dex/dex_types.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

std::unique_ptr<DVMType> DexTypes::parse_type(std::string_view name) {
    switch (name.at(0)) {

        case 'Z':
            return std::make_unique<DVMFundamental>(fundamental_e::BOOLEAN, name);
        case 'B':
            return std::make_unique<DVMFundamental>(fundamental_e::BYTE, name);
        case 'C':
            return std::make_unique<DVMFundamental>(fundamental_e::CHAR, name);
        case 'D':
            return std::make_unique<DVMFundamental>(fundamental_e::DOUBLE, name);
        case 'F':
            return std::make_unique<DVMFundamental>(fundamental_e::FLOAT, name);
        case 'I':
            return std::make_unique<DVMFundamental>(fundamental_e::INT, name);
        case 'J':
            return std::make_unique<DVMFundamental>(fundamental_e::LONG, name);
        case 'S':
            return std::make_unique<DVMFundamental>(fundamental_e::SHORT, name);
        case 'V':
            return std::make_unique<DVMFundamental>(fundamental_e::VOID, name);
        case 'L':
            return std::make_unique<DVMClass>(name);
        case '[':
        {
            size_t depth = 0;
            for (const auto &c : name) {
                if (c == '[') depth++;
                else break;
            }
            std::string_view aux(name.begin()+depth, name.end());
            std::unique_ptr<DVMType> aux_type = parse_type(aux);
            return std::make_unique<DVMArray>(depth, aux_type, name);
        }
        default:
            return std::make_unique<Unknown>(name);
    }
}

void DexTypes::parse_types(common::ShurikenStream& shurikenStream,
                           DexStrings& strings_,
                           std::uint32_t offset_types,
                           std::uint32_t n_of_types) {
    auto my_logger = shuriken::logger();
    my_logger->info("Start parsing types");

    auto current_offset = shurikenStream.tellg();

    std::unique_ptr<DVMType> type;
    std::uint32_t type_id;

    shurikenStream.seekg(offset_types, std::ios_base::beg);

    for (size_t I = 0; I < n_of_types; ++I) {
        shurikenStream.read_data<std::uint32_t>(type_id, sizeof(std::uint32_t));

        type = parse_type(strings_.get_string_by_id(type_id));

        ordered_types.push_back(std::move(type));
    }

    shurikenStream.seekg(current_offset, std::ios_base::beg);
    my_logger->info("Finished parsing types");
}

void DexTypes::to_xml(std::ofstream &fos) {
    fos << "<DexTypes>\n";

    for (size_t I = 0; I < ordered_types.size(); ++I)
    {
        fos << "\t<type>\n";
        fos << "\t\t<id>" << I << "</id>\n";
        fos << "\t\t<value>" << ordered_types[I]->print_type() << "</value>\n";
        fos << "\t</type>\n";
    }

    fos << "</DexTypes>\n";
}