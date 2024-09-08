//
// Created by fare9 on 30/12/23.
//

#include <shuriken/shuriken_cpp_core.h>
#include <chrono>
#include <fmt/core.h>
#include <functional>
#include <iostream>
// Dex & APK stuff
#include <shuriken/analysis/Dex/analysis.h>
#include <shuriken/common/Dex/dvm_types.h>
#include <shuriken/disassembler/Dex/dex_disassembler.h>
#include <shuriken/parser/shuriken_parsers.h>


#include <vector>

void show_help(std::string &prog_name) {
    fmt::println("USAGE: {} <dex/apk file to analyze> [-h] [-c] [-f] [-m] [-b]", prog_name);
    fmt::println(" -h: show file header");
    fmt::println(" -c: show classes from file");
    fmt::println(" -f: show fields from classes (it needs -c)");
    fmt::println(" -m: show methods from classes (it needs -c)");
    fmt::println(" -b: show bytecode from methods (it needs -m)");
    fmt::println(" -D: show the disassembled code from methods (it needs -m)");
    fmt::println(" -B: show the methods as basic blocks (it needs -m)");
    fmt::println(" -x: show the xrefs from classes (it needs -c), from methods (it requires -m) or from fields (it needs -f)");
    fmt::println(" -T: measure and print after the execution the time taken for the analysis");
    fmt::println(" -N: analyze but do not print any information");
}

void parse_dex(std::string& dex_file);
void parse_apk(std::string& apk_file);
void print_header(const shurikenapi::DexHeader& header);
void print_classes(const shurikenapi::IClassManager& classManager);
void print_field(const shurikenapi::IClassField&, size_t index);
void print_method(const shurikenapi::IClassMethod& method, size_t index);
void print_code(std::span<std::uint8_t> bytecode);

bool headers = false;
bool show_classes = false;
bool methods = false;
bool fields = false;
bool code = false;
bool disassembly = false;
bool blocks = false;
bool running_time = false;
bool xrefs = false;
bool no_print = false;

std::unique_ptr<shuriken::parser::apk::Apk> parsed_apk = nullptr;
std::unique_ptr<shuriken::parser::dex::Parser> parsed_dex = nullptr;
std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> disassembler_own = nullptr;
shuriken::disassembler::dex::DexDisassembler * disassembler = nullptr;
std::unique_ptr<shuriken::analysis::dex::Analysis> dex_analysis_own = nullptr;
shuriken::analysis::dex::Analysis * analysis = nullptr;
// std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> disassembler;
// std::unique_ptr<shuriken::analysis::dex::Analysis> dex_analysis;

int main(int argc, char **argv) {
    std::vector<std::string> args{argv, argv + argc};

    auto start_time = std::chrono::high_resolution_clock::now();

    if (args.size() == 1) {
        show_help(args[0]);
        return -1;
    }

    std::unordered_map<std::string, std::function<void()>> options{
            {"-h", [&]() { headers = true; }},
            {"-c", [&]() { show_classes = true; }},
            {"-m", [&]() { methods = true; }},
            {"-f", [&]() { fields = true; }},
            {"-b", [&]() { code = true; }},
            {"-D", [&]() { disassembly = true; }},
            {"-B", [&]() { blocks = true; }},
            {"-x", [&]() { xrefs = true; }},
            {"-T", [&]() { running_time = true; }},
            {"-N", [&]() { no_print = true; }}
    };

    for (const auto &s: args) {
        if (auto it = options.find(s); it != options.end()) {
            it->second();
        }
    }

    try {
        if (args[1].ends_with(".dex")) { // manage dex file :)
            parse_dex(args[1]);
        } else if (args[1].ends_with(".apk")) {
            parse_apk(args[1]);
        std::unique_ptr<shurikenapi::IDex> parsed_dex = shurikenapi::parse_dex(args[1]);
        if (!parsed_dex) {
            fmt::println("Failed to parse dex");
            return -1;
        }

        if (headers) print_header(parsed_dex->getHeader());
        if (show_classes) print_classes(parsed_dex->getClassManager());

        const shurikenapi::IDisassembler& disassembler = parsed_dex->getDisassembler();
        /*
        if (disassembly) {
            disassembler = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(parsed_dex.get());
            disassembler->disassembly_dex();
        }

        if (blocks || xrefs) {
            if (disassembler == nullptr) {
                disassembler = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(parsed_dex.get());
                disassembler->disassembly_dex();
            }
            dex_analysis = std::make_unique<shuriken::analysis::dex::Analysis>(parsed_dex.get(),
                                                                               disassembler.get(),
                                                                               xrefs ? true : false);
            dex_analysis->create_xrefs();
        }
        */
        if (!no_print) {
            auto &header = parsed_dex->getHeader();

            if (headers) print_header(header);
            if (show_classes) print_classes(parsed_dex->getClassManager());
        }
    } catch (std::runtime_error &re) {
        fmt::println("Exception: {}", re.what());
    }

    auto end_time = std::chrono::high_resolution_clock::now();

    if (running_time) {
        // Calculate the duration
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        // Convert duration to hours, minutes, seconds, and milliseconds
        auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
        duration -= hours;
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
        duration -= minutes;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
        duration -= seconds;
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);

        // Print the duration
        fmt::print("Execution time: {:02}h:{:02}m:{:02}s:{:03}ms\n",
                   hours.count(), minutes.count(), seconds.count(), milliseconds.count());
    }

    return 0;
}

void parse_dex(std::string& dex_file) {
    parsed_dex = shuriken::parser::parse_dex(dex_file);

    if (disassembly) {
        disassembler_own = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(parsed_dex.get());
        disassembler_own->disassembly_dex();
        disassembler = disassembler_own.get();
    }

    if (blocks || xrefs) {
        if (disassembler_own == nullptr) {
            disassembler_own = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(parsed_dex.get());
            disassembler_own->disassembly_dex();
        }
        dex_analysis_own = std::make_unique<shuriken::analysis::dex::Analysis>(parsed_dex.get(),
                                                                               disassembler_own.get(),
                                                                               xrefs ? true : false);
        dex_analysis_own->create_xrefs();

        disassembler = disassembler_own.get();
        analysis = dex_analysis_own.get();
    }

    if (!no_print) {
        auto &header = parsed_dex->get_header();

        if (headers) print_header(header);
        if (show_classes) print_classes(parsed_dex->get_classes());
    }
}

void parse_apk(std::string& apk_file) {
    parsed_apk = shuriken::parser::parse_apk(apk_file, xrefs ? true : false);

    disassembler = parsed_apk->get_global_disassembler();
    analysis = parsed_apk->get_global_analysis();

    for (auto & file_name : parsed_apk->get_dex_files_names()) {
        fmt::println("DEX File: {}", file_name);
    }

    if (!no_print) {
        for (auto & file_parser : parsed_apk->get_dex_parsers()) {
            auto & parsed_dex = file_parser.second.get();
            auto & header = parsed_dex.get_header();

            fmt::println("Analysis of file: {}", file_parser.first);
            if (headers) print_header(header);
            if (show_classes) print_classes(parsed_dex.get_classes());
        }
    }

}

void print_header(const shurikenapi::DexHeader& dex_header) {
    fmt::println("Dex Header:");
    fmt::print(" Magic:");
    for (auto b: dex_header.magic) {
        if (isprint(b))
            fmt::print(" {:02X} ({:c})", b, b);
        else
            fmt::print(" {:02X} ( )", b, b);
    }
    fmt::println("\n Checksum:              0x{:X}", static_cast<std::uint32_t>(dex_header.checksum));
    fmt::print(" Signature:");
    for (auto b: dex_header.signature) {
        fmt::print(" {:02X}", b);
    }
    fmt::print("\n File Size:             {}\n", dex_header.file_size);
    fmt::print(" Header Size:           {}\n", dex_header.header_size);
    fmt::print(" Endian Tag:            0x{:X}\n", dex_header.endian_tag);
    fmt::print(" Link offset:           0x{:X}\n", dex_header.link_off);
    fmt::print(" Link Size:             {}\n", dex_header.link_size);
    fmt::print(" Map offset:            0x{:X}\n", dex_header.map_off);
    fmt::print(" String ids offset:     0x{:X}\n", dex_header.string_ids_off);
    fmt::print(" String ids size:       {}\n", dex_header.string_ids_size);
    fmt::print(" Type ids offset:       0x{:X}\n", dex_header.type_ids_off);
    fmt::print(" Type ids size:         {}\n", dex_header.type_ids_size);
    fmt::print(" Proto ids offset:      0x{:X}\n", dex_header.proto_ids_off);
    fmt::print(" Proto ids size:        {}\n", dex_header.proto_ids_size);
    fmt::print(" Field ids offset:      0x{:X}\n", dex_header.field_ids_off);
    fmt::print(" Field ids size:        {}\n", dex_header.field_ids_size);
    fmt::print(" Method ids offset:     0x{:X}\n", dex_header.method_ids_off);
    fmt::print(" Method ids size:       {}\n", dex_header.method_ids_size);
    fmt::print(" Class ids offset:      0x{:X}\n", dex_header.class_defs_off);
    fmt::print(" Class ids size:        {}\n", dex_header.class_defs_size);
    fmt::print(" Data ids offset:       0x{:X}\n", dex_header.data_off);
    fmt::print(" Data ids size:         {}\n", dex_header.data_size);
}



void print_classes(const shurikenapi::IClassManager& classManager) {
    auto classes = classManager.getAllClasses();
    size_t I = 0;
    for (const auto& c : classes) {
        fmt::print("Class #{} data:\n", I);

        fmt::print("\tClass name:            {}\n", c.get().getName());
        fmt::print("\tSuper class:           {}\n", c.get().getSuperClassName());
        fmt::print("\tSource file:           {}\n", c.get().getSourceFileName());
        fmt::print("\tAccess flags:          0x{:X} ({})\n", static_cast<std::uint32_t>(c.get().getAccessFlags()), 
                        shurikenapi::utils::DexFlags2String(c.get().getAccessFlags()));

        fmt::print("\tStatic Fields:\n");
        int staticIdx = 0;
        for (const auto& f : c.get().getStaticFields()) {
             const shurikenapi::IClassField& field = f.get();
            print_field(field, staticIdx++);
        }
        fmt::print("\tInstance Fields:\n");
        int instanceIdx = 0;
        for (const auto& f : c.get().getInstanceFields()) {
            const shurikenapi::IClassField& field = f.get();
            print_field(field, instanceIdx++);
        }

        fmt::print("\tDirect Methods:\n");
        int directIdx = 0;
        for (auto& m : c.get().getDirectMethods()) {
            const shurikenapi::IClassMethod& method = m.get();
            print_method(method, directIdx++);
        }

        fmt::print("\tVirtual Methods:\n");
        int virtualIdx = 0;
        for (auto& m : c.get().getVirtualMethods()) {
            const shurikenapi::IClassMethod& method = m.get();
            print_method(method, virtualIdx++);
        }

        /*
        if (xrefs) {
            fmt::print(" XREFs\n");
            auto class_analysis = analysis->get_class_analysis(class_idx->get_class_name().data());

            auto xrefconstclass = class_analysis->get_xrefconstclass();
            fmt::print("  XREF Const Class:\n");
            for (auto & xref : xrefconstclass) {
                fmt::print("   - {}:{}\n", xref.first->get_full_name(), xref.second);
            }
            auto xrefnewinstance = class_analysis->get_xrefnewinstance();
            fmt::print("  XREF New Instance:\n");
            for (auto & xref : xrefnewinstance) {
                fmt::print("   - {}:{}\n", xref.first->get_full_name(), xref.second);
            }
        }
        */

    }
}

void print_field(const shurikenapi::IClassField& field, size_t j) {
    fmt::print("\t\tField #{}\n", j);
    fmt::print("\t\t\tName:            {}\n", field.getName());
    fmt::print("\t\t\tType:            {}\n", shurikenapi::utils::DexType2String(field.getFieldType().getType()));
    auto dexValue = field.getFieldType().getFundamentalValue();
    if (dexValue.has_value())
        fmt::print("\t\t\tValue:           {}\n", shurikenapi::utils::DexValue2String(*dexValue));
    fmt::print("\t\t\tAccess Flags:    {} ({})\n", static_cast<std::uint32_t>(field.getAccessFlags()),
            shurikenapi::utils::DexFlags2String(field.getAccessFlags()));
    /*
    if (xrefs) {
        fmt::print("   XRefs:\n");
        auto field_analysis = analysis->get_field_analysis(field);
        if (field_analysis == nullptr) return;
        auto xref_read = field_analysis->get_xrefread();
        fmt::print("    Xrefs Read:\n");
        for (auto & xref : xref_read) {
            fmt::print("      {}:{}\n",
                       std::get<shuriken::analysis::dex::MethodAnalysis*>(xref)->get_full_name(),
                       std::get<std::uint64_t>(xref));
        }
        auto xref_write = field_analysis->get_xrefwrite();
        fmt::print("    Xrefs Write:\n");
        for (auto & xref : xref_write) {
            fmt::print("      {}:{}\n",
                       std::get<shuriken::analysis::dex::MethodAnalysis*>(xref)->get_full_name(),
                       std::get<std::uint64_t>(xref));
        }
    }
    */
}

void print_method(const shurikenapi::IClassMethod& method, size_t j) {
    fmt::print("\t\tMethod #{}\n", j);

    fmt::print("\t\t\tMethod name:              {}\n", method.getName());
    fmt::print("\t\t\tMethod demangled name:    {}\n", method.getDemangledName());
    fmt::print("\t\t\tPrototype:                {}\n", method.getPrototype().getString());
    fmt::print("\t\t\t  ReturnType:        {}\n", shurikenapi::utils::DexType2String(method.getPrototype().getReturnType()));
    size_t parameterIdx = 0;
    for (const auto& p : method.getPrototype().getParameters()) {
        fmt::print("\t\t\t  Parameter #{}:      {}\n", parameterIdx++, shurikenapi::utils::DexType2String(p.get()));
    }
    fmt::print("\t\t\tAccess Flags:   0x{:X} ({})\n", static_cast<std::uint32_t>(method.getFlags()),
               shurikenapi::utils::DexFlags2String(method.getFlags()));
    fmt::print("\t\t\tCode size:      {}\n", method.getByteCode().size());
    print_code(method.getByteCode());
    /*
    if (disassembly) {
        fmt::println("Disassembled method:");
        auto disassembled_method = disassembler->get_disassembled_method(method_id->dalvik_name_format());
        if (disassembled_method == nullptr)
            throw std::runtime_error("The method " + std::string(method_id->demangle()) + " was not correctly disassembled");
        fmt::print("{}\n", disassembled_method->print_method());
    }
    if (blocks) {
        auto method_analysis = analysis->get_method(method);
        if (method_analysis == nullptr) return;

        if (method_analysis) {
            fmt::print("\n{}\n", method_analysis->toString());
        }
    }
    if (xrefs) {
        auto method_analysis = analysis->get_method(method);
        if (method_analysis == nullptr) return;

        fmt::print("    XREFs\n");

        auto xrefto = method_analysis->get_xrefto();
        fmt::print("     XREF To:\n");
        for (auto & xref : xrefto) {
                fmt::print("      - {}:{}\n",
                           std::get<shuriken::analysis::dex::MethodAnalysis*>(xref)->get_full_name(),
                           std::get<std::uint64_t>(xref));

        }
        auto xreffrom = method_analysis->get_xreffrom();
        fmt::print("     XREF From:\n");
        for (auto & xref : xreffrom) {
            fmt::print("      - {}:{}\n",
                       std::get<shuriken::analysis::dex::MethodAnalysis*>(xref)->get_full_name(),
                       std::get<std::uint64_t>(xref));

        }
    }
    */
}

void print_code(std::span<std::uint8_t> bytecode) {
    fmt::print("   Code: ");
    size_t j = 0;
    for (auto b: bytecode) {
        fmt::print("{:02X} ", b);
        if (j++ == 8) {
            j = 0;
            fmt::print("\n         ");
        }
    }
    fmt::print("\n");
}
