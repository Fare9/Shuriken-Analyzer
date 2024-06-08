//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file parse-test-dex.cpp
// @brief Simple test for parsing all the DEX files from code
// for the test to be correct all the DEX files must be properly
// parsed

#include "dex-files-folder.inc"
#include "shuriken/parser/shuriken_parsers.h"
#include <iostream>
#include <memory>
#include <vector>

int main() {

    std::vector<std::string> paths = {
            std::string(DEX_FILES_FOLDER) + "_cast.dex",
            std::string(DEX_FILES_FOLDER) + "_double.dex",
            std::string(DEX_FILES_FOLDER) + "_exception.dex",
            std::string(DEX_FILES_FOLDER) + "_float.dex",
            std::string(DEX_FILES_FOLDER) + "_instance.dex",
            std::string(DEX_FILES_FOLDER) + "_int.dex",
            std::string(DEX_FILES_FOLDER) + "_long.dex",
            std::string(DEX_FILES_FOLDER) + "_loop.dex",
            std::string(DEX_FILES_FOLDER) + "_null.dex",
            std::string(DEX_FILES_FOLDER) + "_pi.dex",
    };

    std::unique_ptr<shuriken::parser::dex::Parser> dex_parser = nullptr;

    for (const auto &path: paths) {
        auto name = path.substr(path.find_last_of("/") + 1);
        std::cerr << "Parsing file: " << name << "\n";
        dex_parser = shuriken::parser::parse_dex(path);
        std::cerr << "Parsed file: " << name << "\n";
    }

    return 0;
}
