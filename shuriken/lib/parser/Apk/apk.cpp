//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file apk.cpp

#include "shuriken/parser/Apk/apk.h"
#include "shuriken/common/logger.h"
#include "shuriken/parser/shuriken_parsers.h"

#include "zip.h"
#include <filesystem>
#include <sstream>

using namespace shuriken::parser::apk;

namespace {
    // Function to extract a file from a zip archive
    bool extract_file(zip_t *archive, const char *filename, const std::string &output_path) {
        // Open the file inside the archive
        zip_file_t *file = zip_fopen(archive, filename, 0);
        if (!file) {
            std::cerr << "Failed to open " << filename << " in the archive." << std::endl;
            return false;
        }

        // Get the file info (like size)
        struct zip_stat file_stat;
        zip_stat_init(&file_stat);
        if (zip_stat(archive, filename, 0, &file_stat) == -1) {
            std::cerr << "Failed to get file stats for " << filename << std::endl;
            zip_fclose(file);
            return false;
        }

        // Allocate buffer for file content
        std::vector<char> buffer(file_stat.size);

        // Read the file content
        zip_fread(file, buffer.data(), buffer.size());
        zip_fclose(file);

        // Write the file to the output path
        std::ofstream output_file(output_path, std::ios::binary);
        if (!output_file) {
            std::cerr << "Failed to create output file " << output_path << std::endl;
            return false;
        }
        output_file.write(buffer.data(), buffer.size());
        output_file.close();

        return true;
    }
}// namespace

// Private API
class Apk::ApkExtractor {
private:
    /// @brief path to the apk
    std::string path_to_apk;
    /// @brief path to the temporal file
    std::string path_to_temporal_file;
    /// @brief zip file
    zip_t *apk_file;

    std::vector<std::string_view> dex_file_names;

    /// @brief parsers created during the analysis
    std::unordered_map<std::string,
                       std::unique_ptr<parser::dex::Parser>>
            dex_parsers;
    /// @brief Reference for the map, it does not contain
    /// ownership
    std::unordered_map<std::string,
                       std::reference_wrapper<parser::dex::Parser>>
            dex_parsers_s;
    /// @brief global disassembler
    std::unique_ptr<disassembler::dex::DexDisassembler> global_disassembler;

    /// @brief global analysis
    std::unique_ptr<analysis::dex::Analysis> global_analysis;

public:
    /// @brief Public constructor stores the path to the APK
    ApkExtractor(const char *path_to_apk) {
        if (!std::filesystem::exists(path_to_apk))
            throw std::runtime_error("Error APK provided for the analysis does not exists");
        path_to_temporal_file += std::filesystem::temp_directory_path().c_str();
        path_to_temporal_file += std::filesystem::path::preferred_separator;
        path_to_temporal_file += std::filesystem::path(path_to_apk).stem();
        std::filesystem::create_directories(path_to_temporal_file);

        // open the APK
        int error;
        // open the APK with the zip folder
        apk_file = zip_open(path_to_apk, ZIP_RDONLY, &error);
        if (!apk_file) {
            std::stringstream ss;
            ss << "Error opening the APK file as a zip: " << error;
            throw std::runtime_error(ss.str());
        }
    }

    /// @brief release zip file and so on...
    ~ApkExtractor() {
        // remove the files
        if (std::filesystem::exists(path_to_temporal_file)) {
            for (const auto &file:
                 std::filesystem::directory_iterator(path_to_temporal_file))
                std::filesystem::remove(file.path().c_str());
        }
        zip_close(apk_file);
    }

    void analyze_apk(bool create_xrefs) {
        log(LEVEL::INFO, "Starting the APK analysis of {}", path_to_apk);

        global_disassembler = std::make_unique<disassembler::dex::DexDisassembler>();

        // Get the number of files in the archive
        zip_int64_t num_files = zip_get_num_entries(apk_file, 0);

        for (zip_int64_t i = 0; i < num_files; ++i) {
            std::string name(zip_get_name(apk_file, i, 0));

            if (name.empty() || !name.ends_with(".dex")) continue;

            std::string base_name = std::filesystem::path(name).filename();

            // create the file path in the temporal folder
            std::string file_path = path_to_temporal_file;
            file_path += std::filesystem::path::preferred_separator;
            file_path += base_name;

            log(LEVEL::MYDEBUG, "Analyzing a new dex file {}", name);

            // extract the file in the temporal folder
            extract_file(apk_file, name.c_str(), file_path);

            std::unique_ptr<parser::dex::Parser> current_parser = parse_dex(file_path);

            log(LEVEL::MYDEBUG, "Disassembling a new dex file {}", name);

            global_disassembler->disassemble_new_dex(current_parser.get());

            dex_parsers.insert({name, std::move(current_parser)});
        }

        log(LEVEL::MYDEBUG, "Creating a global analysis for {}", path_to_apk);

        global_analysis = std::make_unique<analysis::dex::Analysis>(global_disassembler.get(), create_xrefs);

        for (auto &dex_parser: dex_parsers) {
            global_analysis->add(dex_parser.second.get());
        }

        global_analysis->create_xrefs();

        log(LEVEL::INFO, "Finished the analysis of the APK {}", path_to_apk);
    }

    std::vector<std::string_view> & get_dex_files_names() {
        if (dex_file_names.empty()) {
            for (auto & parser : dex_parsers)
                dex_file_names.push_back(parser.first);
        }
        return dex_file_names;
    }

    parser::dex::Parser *get_parser_by_file(std::string dex_file) {
        if (!dex_parsers.contains(dex_file)) return nullptr;
        return dex_parsers[dex_file].get();
    }

    std::unordered_map<std::string,
                       std::reference_wrapper<parser::dex::Parser>> &
    get_dex_parsers() {
        if (dex_parsers_s.empty() || dex_parsers_s.size() != dex_parsers.size()) {
            for (auto & parser : dex_parsers) {
                dex_parsers_s.insert({parser.first, std::ref(*parser.second)});
            }
        }
        return dex_parsers_s;
    }

    disassembler::dex::DexDisassembler *get_global_disassembler() {
        return global_disassembler.get();
    }

    analysis::dex::Analysis *get_global_analysis() {
        return global_analysis.get();
    }

    std::string get_path_to_apk() const {
        return path_to_apk;
    }

    std::string get_path_to_temporal_file() const {
        return path_to_temporal_file;
    }
};

// Public API

Apk::Apk(std::unique_ptr<ApkExtractor>& apk_extractor) :
    apk_extractor(std::move(apk_extractor))
{}

Apk::~Apk() = default;

std::vector<std::string_view> & Apk::get_dex_files_names() {
    return apk_extractor->get_dex_files_names();
}

shuriken::parser::dex::Parser *Apk::get_parser_by_file(std::string dex_file) {
    return apk_extractor-> get_parser_by_file(dex_file);
}

std::unordered_map<std::string,
                   std::reference_wrapper<shuriken::parser::dex::Parser>> &
Apk::get_dex_parsers() {
    return apk_extractor->get_dex_parsers();
}

shuriken::disassembler::dex::DexDisassembler *Apk::get_global_disassembler() {
    return apk_extractor->get_global_disassembler();
}

shuriken::analysis::dex::Analysis *Apk::get_global_analysis() {
    return apk_extractor->get_global_analysis();
}


namespace shuriken {
    namespace parser {
        std::unique_ptr<apk::Apk> parse_apk(const std::string &file_path, bool created_xrefs) {
            std::unique_ptr<Apk::ApkExtractor> apkExtractor = std::make_unique<Apk::ApkExtractor>(file_path.c_str());
            apkExtractor->analyze_apk(created_xrefs);
            auto apk = std::make_unique<apk::Apk>(apkExtractor);
            return apk;
        }

        std::unique_ptr<apk::Apk> parse_apk(const char *file_path, bool created_xrefs) {
            std::unique_ptr<Apk::ApkExtractor> apkExtractor = std::make_unique<Apk::ApkExtractor>(file_path);
            apkExtractor->analyze_apk(created_xrefs);
            auto apk = std::make_unique<apk::Apk>(apkExtractor);
            return apk;
        }
    }// namespace parser
}// namespace shuriken
