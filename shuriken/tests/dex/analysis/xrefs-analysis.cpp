//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file xref-analysis.cpp
// @brief Test for the generation of xrefs in shuriken


#include "dex-files-folder.inc"
#include "shuriken/analysis/Dex/analysis.h"
#include "shuriken/disassembler/Dex/dex_disassembler.h"
#include "shuriken/parser/Dex/parser.h"
#include "shuriken/parser/shuriken_parsers.h"

#include <cassert>
#include <iostream>

int main() {
    std::string test_file = std::string(DEX_FILES_FOLDER) + "_instance.dex";

    std::unique_ptr<shuriken::parser::dex::Parser> dex_parser = nullptr;
    std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> dex_disassembler = nullptr;
    std::unique_ptr<shuriken::analysis::dex::Analysis> dex_analysis = nullptr;

    dex_parser = shuriken::parser::parse_dex(test_file);
    dex_disassembler = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(dex_parser.get());

    dex_disassembler->disassembly_dex();

    dex_analysis = std::make_unique<shuriken::analysis::dex::Analysis>(dex_parser.get(),
                                                                       dex_disassembler.get(),
                                                                       true);

    dex_analysis->create_xrefs();

    dex_analysis->get_fields();

    for (auto &clazz: dex_analysis->get_classes()) {
        auto &clazz_value = clazz.second.get();
        std::cout << clazz_value.name() << "\n";
        for (auto &method: clazz_value.get_methods()) {
            auto method_value = method.second;
            if (!method_value->external())
                std::cout << method_value->toString();
        }
    }
    dex_analysis.release();
    return 0;
}
