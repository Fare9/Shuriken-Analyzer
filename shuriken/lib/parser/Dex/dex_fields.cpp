//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file fields.cpp

#include "shuriken/parser/Dex/dex_fields.h"
#include "shuriken/common/logger.h"


using namespace shuriken::parser::dex;

void DexFields::parse_fields(
        common::ShurikenStream& stream,
        DexTypes& types,
        DexStrings& strings,
        std::uint32_t fields_offset,
        std::uint32_t n_of_fields) {
    auto current_offset = stream.tellg();
    auto my_logger = shuriken::logger();
    std::uint16_t class_idx, type_idx;
    std::uint32_t name_idx;
    std::unique_ptr<FieldID> field_id = nullptr;

    my_logger->info("Started parsing of fields at offset {}", fields_offset);

    stream.seekg(fields_offset, std::ios_base::beg);

    for (size_t I = 0; I < n_of_fields; ++I) {
        stream.read_data<std::uint16_t>(class_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint16_t>(type_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint32_t>(name_idx, sizeof(std::uint32_t));

        field_id = std::make_unique<FieldID>(
                types.get_type_by_id(class_idx),
                types.get_type_by_id(type_idx),
                strings.get_string_by_id(name_idx)
                );
        fields.push_back(std::move(field_id));
    }

    my_logger->info("Finished parsing of fields");
    stream.seekg(current_offset, std::ios_base::beg);
}

void DexFields::to_xml(std::ofstream& fos) {
    fos << "<fields>\n";
    for (const auto &field : fields)
    {
        fos << "\t<field>\n";
        fos << "\t\t<type>" << field->field_type()->print_type() << "</type>\n";
        fos << "\t\t<name>" << field->field_name() << "</name>\n";
        fos << "\t\t<class>" << field->field_class()->print_type() << "</class>\n";
        fos << "\t</field>\n";
    }
    fos << "</fields>\n";
}