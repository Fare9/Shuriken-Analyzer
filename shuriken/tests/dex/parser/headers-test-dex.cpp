//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file headers-test-dex.cpp
// @brief Test the values from the parser and check these
// values are correct

#include "dex-files-folder.inc"
#include "shuriken/parser/Dex/parser.h"
#include "shuriken/parser/shuriken_parsers.h"

#include <cassert>

// Useful structures for the test
struct field_data {
    std::string_view name;
    std::uint32_t flags;
    std::string_view type;
};

struct method_data {
    std::string_view name;
    std::string_view type;
    std::uint32_t flags;
    std::uint32_t registers;
    std::uint32_t insns_size;
};


// header data
std::uint8_t magic[] = {'d', 'e', 'x', '\n', '0', '3', '5', '\0'};
std::int32_t checksum = 0xe4eefae3;
std::uint32_t file_size = 1624;
std::uint32_t header_size = 112;

std::uint32_t link_size = 0;
std::uint32_t link_off = 0;
std::uint32_t string_ids_size = 33;
std::uint32_t string_ids_off = 112;
std::uint32_t type_ids_size = 9;
std::uint32_t type_ids_off = 244;
std::uint32_t proto_ids_size = 7;
std::uint32_t proto_ids_off = 280;
std::uint32_t field_ids_size = 3;
std::uint32_t field_ids_off = 364;
std::uint32_t method_ids_size = 10;
std::uint32_t method_ids_off = 388;
std::uint32_t class_defs_size = 1;
std::uint32_t class_defs_off = 468;

// class data
std::string_view class_descriptor = "LDexParserTest;";
std::string_view super_class_name = "Ljava/lang/Object;";
std::uint32_t ACCESS_FLAGS = 0x0001;

struct field_data fields[2] = {
        {.name = "field1",
         .flags = 0x0002,
         .type = "I"},
        {.name = "field2",
         .flags = 0x0002,
         .type = "Ljava/lang/String;"}};

struct method_data methods[4] = {
        {.name = "<init>",
         .type = "V",// provided as a shorty_idx
         .flags = 0x10001,
         .registers = 2,
         .insns_size = 12 * 2},
        {.name = "calculateSum",
         .type = "III",// provided as a shorty_idx
         .flags = 0x0002,
         .registers = 7,
         .insns_size = 47 * 2},
        {.name = "main",
         .type = "VL",// provided as a shorty_idx
         .flags = 0x0009,
         .registers = 3,
         .insns_size = 16 * 2},
        {.name = "printMessage",
         .type = "V",// provided as a shorty_idx
         .flags = 0x0002,
         .registers = 4,
         .insns_size = 60 * 2}};


void check_header(shuriken::parser::dex::DexHeader &header);
void check_class(shuriken::parser::dex::DexClasses &classes);

int main() {
    std::string test_file = DEX_FILES_FOLDER
            "DexParserTest.dex";

    std::unique_ptr<shuriken::parser::dex::Parser> dex_parser =
            shuriken::parser::parse_dex(test_file);

    auto &header = dex_parser->get_header();
    auto &classes = dex_parser->get_classes();


    check_header(header);
    check_class(classes);

    return 0;
}


void check_header(shuriken::parser::dex::DexHeader &header) {
    auto &dex_header = header.get_dex_header_const();

    assert(memcmp(static_cast<const void *>(magic),
                  static_cast<const void *>(dex_header.magic),
                  sizeof(magic)) == 0 &&
           "Error header magic is incorrect");
    assert(checksum == dex_header.checksum && "Error checksum incorrect");
    assert(file_size == dex_header.file_size && "Error file_size incorrect");
    assert(header_size == dex_header.header_size && "Error header_size incorrect");
    assert(link_size == dex_header.link_size && "Error link_size incorrect");
    assert(link_off == dex_header.link_off && "Error link_off incorrect");
    assert(string_ids_size == dex_header.string_ids_size && "Error string_ids_size incorrect");
    assert(string_ids_off == dex_header.string_ids_off && "Error string_ids_off incorrect");
    assert(type_ids_size == dex_header.type_ids_size && "Error type_ids_size incorrect");
    assert(type_ids_off == dex_header.type_ids_off && "Error type_ids_off incorrect");
    assert(proto_ids_size == dex_header.proto_ids_size && "Error proto_ids_size incorrect");
    assert(proto_ids_off == dex_header.proto_ids_off && "Error proto_ids_off incorrect");
    assert(field_ids_size == dex_header.field_ids_size && "Error field_ids_size incorrect");
    assert(field_ids_off == dex_header.field_ids_off && "Error field_ids_off incorrect");
    assert(method_ids_size == dex_header.method_ids_size && "Error method_ids_size incorrect");
    assert(method_ids_off == dex_header.method_ids_off && "Error method_ids_off incorrect");
    assert(class_defs_size == dex_header.class_defs_size && "Error class_defs_size incorrect");
    assert(class_defs_off == dex_header.class_defs_off && "Error class_defs_off incorrect");
}


void check_class(shuriken::parser::dex::DexClasses &classes) {

    for (auto &class_def: classes.get_classdefs()) {
        const auto class_idx = class_def.get_class_idx();
        const auto super_class = class_def.get_superclass();
        std::string_view source_file = class_def.get_source_file();
        auto access_flags = class_def.get_access_flags();

        assert(class_idx->get_raw_type() == class_descriptor && "Error class_descriptor is not correct");
        assert(super_class->get_raw_type() == super_class_name && "Error super_class_name is not correct");
        assert(ACCESS_FLAGS == static_cast<std::uint32_t>(access_flags) && "Error access flags are not correct");

        auto &class_data_item = class_def.get_class_data_item();

        for (size_t i = 0, e = class_data_item.get_number_of_instance_fields(); i < e; i++) {
            auto field = class_data_item.get_instance_field_by_id(i);
            assert(fields[i].flags == static_cast<std::uint32_t>(field->get_flags()) && "Error field flags are not correct");
            assert(fields[i].name == field->get_field()->field_name() && "Error field name is not correct");
            assert(fields[i].type == field->get_field()->field_type()->get_raw_type() && "Error field type is not correct");
        }

        for (size_t i = 0, e = class_data_item.get_number_of_direct_methods(); i < e; i++) {
            auto method = class_data_item.get_direct_method_by_id(i);
            assert(methods[i].name == method->getMethodID()->get_method_name() && "Error method name not correct");
            assert(methods[i].type == method->getMethodID()->get_prototype()->get_shorty_idx() && "Error method prototype not correct");
            assert(methods[i].flags == static_cast<std::uint32_t>(method->get_flags()) && "Error method flags are not correct");
            assert(methods[i].registers == method->get_code_item()->get_registers_size() && "Error method register size not correct");
            assert(methods[i].insns_size == method->get_code_item()->get_bytecode().size() && "Error method size not correct");
        }
    }
}