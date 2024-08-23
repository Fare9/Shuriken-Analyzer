//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file apk.cpp

#include "shuriken/parser/Apk/apk.h"
#include "shuriken/common/logger.h"
#include "shuriken/parser/shuriken_parsers.h"

#include "apk_extractor.h"

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
ApkExtractor::ApkExtractor(const char *path_to_apk) : path_to_apk(path_to_apk) {
    if (!std::filesystem::exists(path_to_apk))
        throw std::runtime_error("Error APK provided for the analysis does not exists");
    path_to_temporal_file += std::filesystem::temp_directory_path().c_str();
    path_to_temporal_file += std::filesystem::path::preferred_separator;
    path_to_temporal_file += std::filesystem::path(path_to_apk).stem();

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

ApkExtractor::~ApkExtractor() {
    // remove the files
    if (std::filesystem::exists(path_to_temporal_file)) {
        for (const auto &file:
             std::filesystem::directory_iterator(path_to_temporal_file))
            std::filesystem::remove(file.path().c_str());
    }
    zip_close(apk_file);
}

void ApkExtractor::analyze_apk(bool create_xrefs) {
    log(LEVEL::INFO, "Starting the APK analysis of {}", path_to_apk);

    global_disassembler = std::make_unique<disassembler::dex::DexDisassembler>();

    // Get the number of files in the archive
    zip_int64_t num_files = zip_get_num_entries(apk_file, 0);

    for (zip_int64_t i = 0; i < num_files; ++i) {
        std::string name(zip_get_name(apk_file, i, 0));

        if (name.empty() || !name.ends_with(".dex")) continue;

        // create the file path in the temporal folder
        std::string file_path = path_to_temporal_file;
        file_path += std::filesystem::path::preferred_separator;
        file_path += name;

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

std::unordered_map<std::string,
                   std::unique_ptr<shuriken::parser::dex::Parser>> &
ApkExtractor::retrieve_parsers() {
    return dex_parsers;
}

std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> &
ApkExtractor::retrieve_disassembler() {
    return global_disassembler;
}

std::unique_ptr<shuriken::analysis::dex::Analysis> &
ApkExtractor::retrieve_analysis() {
    return global_analysis;
}

std::string ApkExtractor::get_path_to_apk() const {
    return path_to_apk;
}

std::string ApkExtractor::get_path_to_temporal_file() const {
    return path_to_temporal_file;
}

// Public API

Apk::Apk(const char *apk_path,
         std::unordered_map<std::string,
                            std::unique_ptr<parser::dex::Parser>> &dex_files,
         std::unique_ptr<disassembler::dex::DexDisassembler> &global_disassembler,
         std::unique_ptr<analysis::dex::Analysis> &global_analysis) : apk_path(apk_path),
                                                                      dex_files(std::move(dex_files)), global_disassembler(std::move(global_disassembler)),
                                                                      global_analysis(std::move(global_analysis)) {
    for (auto &dex_file: this->dex_files)
        dex_files_s.insert({dex_file.first, std::ref(*dex_file.second)});
}

shuriken::parser::dex::Parser *Apk::get_parser_by_file(std::string dex_file) {
    if (!dex_files.contains(dex_file)) return nullptr;
    return dex_files[dex_file].get();
}

std::unordered_map<std::string,
                   std::reference_wrapper<shuriken::parser::dex::Parser>> &
Apk::get_dex_parsers() {
    return dex_files_s;
}

shuriken::disassembler::dex::DexDisassembler *Apk::get_global_disassembler() {
    return global_disassembler.get();
}

shuriken::analysis::dex::Analysis *Apk::get_global_analysis() {
    return global_analysis.get();
}


namespace shuriken {
    namespace parser {
        std::unique_ptr<apk::Apk> parse_apk(const std::string &file_path, bool created_xrefs) {
            ApkExtractor apkExtractor(file_path.c_str());
            apkExtractor.analyze_apk(created_xrefs);
            auto apk = std::make_unique<apk::Apk>(file_path.c_str(),
                                                  apkExtractor.retrieve_parsers(),
                                                  apkExtractor.retrieve_disassembler(),
                                                  apkExtractor.retrieve_analysis());
            return apk;
        }

        std::unique_ptr<apk::Apk> parse_apk(const char *file_path, bool created_xrefs) {
            ApkExtractor apkExtractor(file_path);
            apkExtractor.analyze_apk(created_xrefs);
            auto apk = std::make_unique<apk::Apk>(file_path,
                                                  apkExtractor.retrieve_parsers(),
                                                  apkExtractor.retrieve_disassembler(),
                                                  apkExtractor.retrieve_analysis());
            return apk;
        }
    }// namespace parser
}// namespace shuriken
