//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file analyze-simple-zip.c
// @brief Test for loading and analyzing a simple zip file with DEX files inside.

#include "dex-files-folder.inc"
#include "shuriken/parser/shuriken_parsers.h"
#include <iostream>
#include <unordered_map>


int main() {
    std::string zip_file = std::string(DEX_FILES_FOLDER) + "test_zip.zip";

    auto apk_analysis = shuriken::parser::parse_apk(zip_file, false);

    auto analysis_object = apk_analysis->get_global_analysis();

    for (auto clazz : analysis_object->get_classes()) {
        auto & class_analysis = clazz.second.get();
        std::cout << class_analysis.name() << "\n";
        std::cout << "Number of methods: " << class_analysis.get_nb_methods() << "\n";
        std::cout << "Number of fields: " << class_analysis.get_nb_fields() << "\n";
        for (auto method : class_analysis.get_methods()) {
            auto method_analysis = method.second;
            std::cout << "\t" << method_analysis->get_name() << ",";
            std::cout << method_analysis->get_descriptor() << ",";
            std::cout << method_analysis->external() << "\n";
        }
    }

    return 0;
}