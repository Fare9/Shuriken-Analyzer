//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file apk.h
// @brief File to analyze APK files, an APK file will contain
// information from all the DEX files from the APK.

#ifndef SHURIKENPROJECT_APK_H
#define SHURIKENPROJECT_APK_H

#include "shuriken/analysis/Dex/analysis.h"
#include "shuriken/disassembler/Dex/dex_disassembler.h"
#include "shuriken/parser/Dex/parser.h"
#include <unordered_map>


namespace shuriken::parser::apk {

    using namespace shuriken::parser;
    using namespace shuriken::disassembler;
    using namespace shuriken::analysis;

    // @brief An APK will be the union of different components that
    // we will work with, this will involve the use of:
    // - DEX files.
    // - SO (ELF) files (not implemented yet).
    // - XML file: for the AndroidManifest.xml.
    class Apk {
    public:
        class ApkExtractor;
    private:
        std::unique_ptr<ApkExtractor> apk_extractor;
    public:
        Apk(std::unique_ptr<ApkExtractor>& apk_extractor);

        /**
         * @brief Destructor for the APK object, it removes all the
         * temporal files.
         */
        ~Apk();

        /**
         * @return name of all the DEX files found in APK
         */
        std::vector<std::string_view> & get_dex_files_names();
        /**
         * @param dex_file file to retrieve its parser
         * @return pointer to a Parser object, or null
         */
        parser::dex::Parser *get_parser_by_file(std::string dex_file);

        /**
         * @return reference to the map with the parser objects
         */
        std::unordered_map<std::string,
                           std::reference_wrapper<parser::dex::Parser>> &
        get_dex_parsers();

        /**
         * @return a global disassembler with the disassembly
         * from all the DEX files.
         */
        disassembler::dex::DexDisassembler *get_global_disassembler();

        /**
         * @return get the global analysis from all the DEX
         * files.
         */
        analysis::dex::Analysis *get_global_analysis();
    };
}// namespace shuriken::parser::apk

#endif//SHURIKENPROJECT_APK_H
