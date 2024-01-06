//
// Created by fare9 on 30/12/23.
//

#include <iostream>
#include <vector>
#include <shuriken/parser/shuriken_parsers.h>
#include <shuriken/parser/Dex/parser.h>
#include <shuriken/parser/Dex/dvm_types.h>
#include <fmt/core.h>


void show_help(std::string& prog_name) {
    fmt::println("USAGE: {} <file_to_analyze> [-h] [-c] [-f] [-m] [-b]", prog_name);
    fmt::println("\t-h: show file header");
    fmt::println("\t-c: show classes from file");
    fmt::println("\t-f: show fields from classes (it needs -c)");
    fmt::println("\t-m: show methods from classes (it needs -c)");
    fmt::println("\t-b: show bytecode from methods (it needs -m)");
}

void print_header(shuriken::parser::dex::Header&);
void print_classes(shuriken::parser::dex::Classes&);
void print_method(shuriken::parser::dex::EncodedMethod*, size_t);
void print_field(shuriken::parser::dex::EncodedField*, size_t);
void print_code(std::span<std::uint8_t>);

bool headers = false;
bool show_classes = false;
bool methods = false;
bool fields = false;
bool code = false;

int
main(int argc, char ** argv) {
    std::vector<std::string> args {argv, argv + argc};

    if (args.size() == 1) {
        show_help(args[0]);
        return -1;
    }

    for (auto & s : args) {
        if (s == "-h")
            headers = true;
        else if (s == "-c")
            show_classes = true;
        else if (s == "-m")
            methods = true;
        else if (s == "-f")
            fields = true;
        else if (s == "-b")
            code = true;
    }

    try {
        auto parsed_dex = shuriken::parser::parse_dex(args[1]);

        auto& header = parsed_dex->get_header();

        if (headers) print_header(header);
        if (show_classes) print_classes(parsed_dex->get_classes());
    } catch (std::runtime_error& re) {

    }

}

void print_header(shuriken::parser::dex::Header& header) {
    auto& dex_header = header.get_dex_header();
    fmt::println("Dex Header:");
    fmt::print("\tMagic:");
    for (auto b : dex_header.magic) {
        if (isprint(b))
            fmt::print(" {:02X} ({:c})", b, b);
        else
            fmt::print(" {:02X} ( )", b, b);
    }
    fmt::println("\n\tChecksum:              0x{:X}", static_cast<std::uint32_t>(dex_header.checksum));
    fmt::print("\tSignature:");
    for (auto b : dex_header.signature) {
        fmt::print(" {:02X}", b);
    }
    fmt::print("\n\tFile Size:             {}\n", dex_header.file_size);
    fmt::print("\tHeader Size:           {}\n", dex_header.header_size);
    fmt::print("\tEndian Tag:            0x{:X}\n", dex_header.endian_tag);
    fmt::print("\tLink offset:           0x{:X}\n", dex_header.link_off);
    fmt::print("\tLink Size:             {}\n", dex_header.link_size);
    fmt::print("\tMap offset:            0x{:X}\n", dex_header.map_off);
    fmt::print("\tString ids offset:     0x{:X}\n", dex_header.string_ids_off);
    fmt::print("\tString ids size:       {}\n", dex_header.string_ids_size);
    fmt::print("\tType ids offset:       0x{:X}\n", dex_header.type_ids_off);
    fmt::print("\tType ids size:         {}\n", dex_header.type_ids_size);
    fmt::print("\tProto ids offset:      0x{:X}\n", dex_header.proto_ids_off);
    fmt::print("\tProto ids size:        {}\n", dex_header.proto_ids_size);
    fmt::print("\tField ids offset:      0x{:X}\n", dex_header.field_ids_off);
    fmt::print("\tField ids size:        {}\n", dex_header.field_ids_size);
    fmt::print("\tMethod ids offset:     0x{:X}\n", dex_header.method_ids_off);
    fmt::print("\tMethod ids size:       {}\n", dex_header.method_ids_size);
    fmt::print("\tClass ids offset:      0x{:X}\n", dex_header.class_defs_off);
    fmt::print("\tClass ids size:        {}\n", dex_header.class_defs_size);
    fmt::print("\tData ids offset:       0x{:X}\n", dex_header.data_off);
    fmt::print("\tData ids size:         {}\n", dex_header.data_size);
}

void print_classes(shuriken::parser::dex::Classes& classes) {
    size_t I = 0;
    for (auto& c : classes.get_classdefs()) {
        fmt::print("Class #{} data:\n", I);

        const auto class_def = c.get();

        const auto class_idx = class_def->get_class_idx();
        const auto super_class = class_def->get_superclass();
        std::string_view source_file = class_def->get_source_file();
        auto access_flags = class_def->get_access_flags();

        fmt::print("\tClass name:            {}\n", class_idx->get_class_name());
        fmt::print("\tSuper class:           {}\n", super_class->get_class_name());
        if (!source_file.empty())
            fmt::print("\tSource file:           {}\n", source_file);
        fmt::print("\tAccess flags:          0x{:X} ({})\n", static_cast<std::uint32_t>(access_flags),
                   shuriken::dex::Utils::get_types_as_string(access_flags));

        auto& class_def_struct = class_def->get_class_def_struct();
        fmt::print("\tSuper class idx:       {}\n", class_def_struct.superclass_idx);
        fmt::print("\tInterfacess off:       0x{:X}\n", class_def_struct.interfaces_off);
        fmt::print("\tAnnotations off:       0x{:X}\n", class_def_struct.annotations_off);
        fmt::print("\tClass data off:        0x{:X}\n", class_def_struct.class_data_off);
        fmt::print("\tStatic values off:     0x{:X}\n", class_def_struct.static_values_off);

        auto& class_data_item = class_def->get_class_data_item();

        fmt::print("\tStatic fields size:    {}\n", class_data_item.get_number_of_static_fields());
        fmt::print("\tInstance fields size:  {}\n", class_data_item.get_number_of_instance_fields());
        fmt::print("\tDirect methods size:   {}\n", class_data_item.get_number_of_direct_methods());
        fmt::print("\tVirtual methods size:  {}\n", class_data_item.get_number_of_virtual_methods());


        if (fields) {
            fmt::print("\tStatic Fields:\n");
            for (size_t j = 0, e = class_data_item.get_number_of_static_fields(); j < e; j++) {
                auto field = class_data_item.get_static_field_by_id(j);
                print_field(field, j);
            }

            fmt::print("\tInstance Fields:\n");
            for (size_t j = 0, e = class_data_item.get_number_of_instance_fields(); j < e; j++) {
                auto field = class_data_item.get_instance_field_by_id(j);
                print_field(field, j);
            }
        }

        if (methods) {
            fmt::print("\tDirect Methods:\n");
            for (size_t j = 0, e = class_data_item.get_number_of_direct_methods(); j < e; j++) {
                auto method = class_data_item.get_direct_method_by_id(j);
                print_method(method, j);
            }

            fmt::print("\tVirtual Methods:\n");
            for (size_t j = 0, e = class_data_item.get_number_of_virtual_methods(); j < e; j++) {
                auto method = class_data_item.get_virtual_method_by_id(j);
                print_method(method, j);
            }
        }
    }
}

void print_field(shuriken::parser::dex::EncodedField* field, size_t j) {
    fmt::print("\t\tField #{}\n", j);
    fmt::print("\t\t\tName:            {}\n", field->get_field()->field_name());
    fmt::print("\t\t\tType:            {}\n", field->get_field()->field_type()->get_raw_type());
    fmt::print("\t\t\tAccess Flags:    {} ({})\n", static_cast<std::uint32_t>(field->get_flags()),
               shuriken::dex::Utils::get_types_as_string(field->get_flags()));

}

void print_method(shuriken::parser::dex::EncodedMethod* method, size_t j) {
    fmt::print("\t\tMethod #{}\n", j);
    auto method_id = method->getMethodID();
    fmt::print("\t\t\tMethod name:    {}\n", method_id->get_method_name());
    fmt::print("\t\t\tPrototype:      (");
    for (auto p : method_id->get_prototype()->get_parameters()) {
        fmt::print("{}", p->get_raw_type());
    }
    fmt::print("){}\n", method_id->get_prototype()->get_return_type()->get_raw_type());
    fmt::print("\t\t\tAccess Flags:   0x{:X} ({})\n", static_cast<std::uint32_t>(method->get_flags()),
               shuriken::dex::Utils::get_types_as_string(method->get_flags()));
    auto code_item_struct = method->get_code_item();
    fmt::print("\t\t\tRegisters:      {}\n", code_item_struct->get_registers_size());
    fmt::print("\t\t\tIns:            {}\n", code_item_struct->get_incomings_args());
    fmt::print("\t\t\tOuts:           {}\n", code_item_struct->get_outgoing_args());
    fmt::print("\t\t\tCode size:      {}\n", code_item_struct->get_instructions_size());
    if (code) {
        print_code(code_item_struct->get_bytecode());
    }
}

void print_code(std::span<std::uint8_t> bytecode) {
    fmt::print("\t\t\tCode: ");
    size_t j = 0;
    for (auto b : bytecode) {
        fmt::print("{:02X} ", b);
        if (j++ == 8) {
            j = 0;
            fmt::print("\n\t\t\t      ");
        }
    }
    fmt::print("\n");
}