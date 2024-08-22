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
    private:
        /// @brief path to the apk
        std::string apk_path;
        /// @brief path to a temporal file
        std::string temporal_file_path;
        /// @brief Map with all the DEX files inside of the Apk
        std::unordered_map<std::string,
                           std::unique_ptr<parser::dex::Parser>>
                dex_files;
        /// @brief A Global disassembler
        std::unique_ptr<disassembler::dex::DexDisassembler> global_disassembler;
        /// @brief A Global analysis for DEX
        std::unique_ptr<analysis::dex::Analysis> global_analysis;

    public:
        /**
         * Constructor for the APK Object
         *
         * @param path_to_apk path to the apk file
         */
        Apk(const char *path_to_apk);

        /**
         * Destructor for the APK object, it removes all the
         * temporal files.
         */
        ~Apk();

        /**
         * @brief Analyze the given apk file for extracting
         * all the DEX files, the AndroidManifest.xml and
         * all the .so files (ELF).
         */
        void analyze_apk_file(bool create_xrefs);

        /**
         * @return a global disassembler with the disassembly
         * from all the DEX files.
         */
        disassembler::dex::DexDisassembler * get_global_disassembler();

        /**
         * @return get the global analysis from all the DEX
         * files.
         */
        analysis::dex::Analysis * get_global_analysis();
    };
}// namespace shuriken::parser::apk

#endif//SHURIKENPROJECT_APK_H
