//
// Created by fare9 on 23/08/24.
//

#ifndef SHURIKENPROJECT_APK_EXTRACTOR_H
#define SHURIKENPROJECT_APK_EXTRACTOR_H

#include <memory>
#include <string>
#include <unordered_map>

#include "shuriken/analysis/Dex/analysis.h"
#include "shuriken/disassembler/Dex/dex_disassembler.h"
#include "shuriken/parser/Dex/parser.h"
#include "zip.h"

namespace shuriken::parser::apk {

    using namespace shuriken::parser;
    using namespace shuriken::disassembler;
    using namespace shuriken::analysis;

    class ApkExtractor {
    private:
        /// @brief path to the apk
        std::string path_to_apk;
        /// @brief path to the temporal file
        std::string path_to_temporal_file;
        /// @brief zip file
        zip_t *apk_file;

        /// @brief parsers created during the analysis
        std::unordered_map<std::string,
                           std::unique_ptr<parser::dex::Parser>>
                dex_parsers;

        /// @brief global disassembler
        std::unique_ptr<disassembler::dex::DexDisassembler> global_disassembler;

        /// @brief global analysis
        std::unique_ptr<analysis::dex::Analysis> global_analysis;

    public:
        /// @brief Public constructor stores the path to the APK
        ApkExtractor(const char *path_to_apk);

        /// @brief release zip file and so on...
        ~ApkExtractor();

        void analyze_apk(bool create_xrefs);

        std::unordered_map<std::string,
                           std::unique_ptr<parser::dex::Parser>> &
        retrieve_parsers();

        std::unique_ptr<disassembler::dex::DexDisassembler> &
        retrieve_disassembler();

        std::unique_ptr<analysis::dex::Analysis> &
        retrieve_analysis();

        std::string get_path_to_apk() const;

        std::string get_path_to_temporal_file() const;
    };

}// namespace shuriken::parser::apk

#endif//SHURIKENPROJECT_APK_EXTRACTOR_H
