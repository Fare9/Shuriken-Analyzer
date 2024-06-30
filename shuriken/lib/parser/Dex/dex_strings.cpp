//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file strings.cpp

#include "shuriken/parser/Dex/dex_strings.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

namespace {
    void write_uleb128(std::ofstream &fos, size_t x) {
        uint8_t b = 0;
        do {
            b = x & 0x7fU;
            if (x >>= 7)
                b |= 0x80U;
            fos.write(reinterpret_cast<const char *>(&b), sizeof(uint8_t));
        } while (x);
    }
}// namespace

void DexStrings::parse_strings(common::ShurikenStream &shuriken_stream,
                               std::uint32_t strings_offset,
                               std::uint32_t n_of_strings) {
    auto my_logger = shuriken::logger();
    my_logger->info("Start parsing strings");

    auto current_offset = shuriken_stream.tellg();
    std::uint32_t str_offset;// we will read offsets

    // move pointer to the given offset
    shuriken_stream.seekg_safe(strings_offset, std::ios_base::beg);

    // read the DexStrings by offset
    for (size_t I = 0; I < n_of_strings; ++I) {
        shuriken_stream.read_data<std::uint32_t>(str_offset, sizeof(std::uint32_t));

        if (str_offset > shuriken_stream.get_file_size())
            throw std::runtime_error("Error string offset out of bound");

        dex_strings.emplace_back(shuriken_stream.read_dex_string(str_offset));
    }
    // create a string_view version of the DexStrings
    for (auto &str: dex_strings) {
        dex_strings_view.emplace_back(str);
    }

    shuriken_stream.seekg(current_offset, std::ios_base::beg);
    my_logger->info("Finished parsing strings");
}

void DexStrings::to_xml(std::ofstream &fos) {
    fos << "<DexStrings>\n";
    for (size_t I = 0, E = dex_strings_view.size(); I < E; I++) {
        fos << "\t<string>\n";
        fos << "\t\t<id>" << I << "</id>\n";
        fos << "\t\t<value>" << dex_strings_view[I] << "</value>\n";
        fos << "\t</string>\n";
    }
    fos << "</DexStrings>\n";
}

void DexStrings::dump_binary(std::ofstream &fos, std::int64_t offset) {
    auto current_offset = fos.tellp();

    fos.seekp(offset);

    for (const auto &s: dex_strings) {
        ::write_uleb128(fos, s.size());
        fos.write(s.c_str(), s.size());
    }

    fos.seekp(current_offset);
}

std::string_view DexStrings::get_string_by_id(std::uint32_t str_id) const {
    if (str_id >= dex_strings_view.size())
        throw std::runtime_error("Error id of string out of bound");
    return dex_strings_view.at(str_id);
}

size_t DexStrings::get_number_of_strings() const {
    return dex_strings_view.size();
}

std::int64_t DexStrings::get_id_by_string(std::string_view str) const {
    auto it = std::ranges::find(dex_strings_view, str);

    if (it == dex_strings_view.end())
        return -1;

    return std::distance(dex_strings_view.begin(), it);
}

const std::vector<std::string_view> DexStrings::get_strings() const {
    return dex_strings_view;
}

std::uint32_t DexStrings::add_string(std::string str) {
    // check if the string is already in the table
    auto value = get_id_by_string(str);
    if (value != -1)
        return static_cast<std::uint32_t>(value);
    // if it doesn´t exist, add it and return the id
    dex_strings.push_back(str);
    dex_strings_view.push_back(dex_strings.back());
    return static_cast<std::uint32_t>(dex_strings.size() - 1);
}