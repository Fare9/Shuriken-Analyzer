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

Apk::Apk(const char *path_to_apk) : apk_path(path_to_apk) {
    if (!std::filesystem::exists(path_to_apk))
        throw std::runtime_error("Error APK provided for the analysis does not exists");
    temporal_file_path += std::filesystem::temp_directory_path().c_str();
    temporal_file_path += std::filesystem::path::preferred_separator;
    temporal_file_path += std::filesystem::path(path_to_apk).stem();
}

Apk::~Apk() {
    if (std::filesystem::exists(temporal_file_path)) {
        for (const auto &file: std::filesystem::directory_iterator(temporal_file_path))
            std::filesystem::remove(file.path().c_str());
        std::filesystem::remove(temporal_file_path);
    }
}

void Apk::analyze_apk_file(bool create_xrefs) {
    zip_t *apk_file;

    int error;
    // open the APK with the zip folder
    apk_file = zip_open(apk_path.c_str(), ZIP_RDONLY, &error);
    if (!apk_file) {
        std::stringstream ss;
        ss << "Error opening the APK file as a zip: " << error;
        throw std::runtime_error(ss.str());
    }

    log(LEVEL::INFO, "Starting the APK analysis of {}", apk_path);

    global_disassembler = std::make_unique<disassembler::dex::DexDisassembler>();

    // Get the number of files in the archive
    zip_int64_t num_files = zip_get_num_entries(apk_file, 0);

    for (zip_int64_t i = 0; i < num_files; ++i) {
        std::string name(zip_get_name(apk_file, i, 0));

        if (name.empty() || !name.ends_with(".dex")) continue;

        // create the file path in the temporal folder
        std::string file_path = temporal_file_path;
        file_path += std::filesystem::path::preferred_separator;
        file_path += name;

        log(LEVEL::MYDEBUG, "Analyzing a new dex file {}", name);

        // extract the file in the temporal folder
        extract_file(apk_file, name.c_str(), file_path);

        std::unique_ptr<parser::dex::Parser> current_parser = parse_dex(file_path);

        log(LEVEL::MYDEBUG, "Disassembling a new dex file {}", name);

        global_disassembler->disassemble_new_dex(current_parser.get());

        dex_files.insert({name, std::move(current_parser)});
    }

    log(LEVEL::MYDEBUG, "Creating a global analysis for {}", apk_path);

    global_analysis = std::make_unique<analysis::dex::Analysis>(global_disassembler.get(), create_xrefs);

    for (auto &dex_parsers: dex_files) {
        global_analysis->add(dex_parsers.second.get());
    }

    global_analysis->create_xrefs();

    zip_close(apk_file);

    log(LEVEL::INFO, "Finished the analysis of the APK {}", apk_path);
}


namespace shuriken {
    namespace parser {
        std::unique_ptr<apk::Apk> parse_apk(const std::string &file_path, bool created_xrefs) {
            auto apk = std::make_unique<apk::Apk>(file_path.c_str());
            apk->analyze_apk_file(created_xrefs);
            return apk;
        }

        std::unique_ptr<apk::Apk> parse_apk(const char *file_path, bool created_xrefs) {
            auto apk = std::make_unique<apk::Apk>(file_path);
            apk->analyze_apk_file(created_xrefs);
            return apk;
        }
    }// namespace parser
}// namespace shuriken
