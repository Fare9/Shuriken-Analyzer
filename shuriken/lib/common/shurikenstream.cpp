//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file shurikenstream.cpp
#include "shuriken/common/shurikenstream.h"

using namespace shuriken::common;

void ShurikenStream::initialize() {
    auto curr_pointer = input_file.tellg();

    // obtain the size
    input_file.seekg(0, std::ios::beg);
    auto fsize = input_file.tellg();
    input_file.seekg(0, std::ios::end);
    fsize = input_file.tellg() - fsize;
    // return to current pointer
    input_file.seekg(curr_pointer, std::ios::beg);

    file_size = static_cast<std::size_t>(fsize);
}

std::uint64_t ShurikenStream::read_uleb128()
{
    std::uint64_t value = 0;
    unsigned shift = 0;
    std::int8_t byte_read;

    do
    {
        read_data<std::int8_t>(byte_read, sizeof(std::int8_t));
        value |= static_cast<std::uint64_t>(byte_read & 0x7f) << shift;
        shift += 7;
    } while (byte_read & 0x80);

    return value;
}

std::int64_t ShurikenStream::read_sleb128()
{
    std::int64_t value = 0;
    unsigned shift = 0;
    std::int8_t byte_read;

    do
    {
        read_data<std::int8_t>(byte_read, sizeof(std::int8_t));
        value |= static_cast<std::uint64_t>(byte_read & 0x7f) << shift;
        shift += 7;
    } while (byte_read & 0x80);

    // sign extend negative numbers
    if ((byte_read & 0x40))
        value |= static_cast<std::int64_t>(-1) << shift;

    return value;
}

std::string ShurikenStream::read_ansii_string(std::int64_t offset) {
    std::string new_str = "";
    std::int8_t character = -1;
    std::uint64_t utf16_size;

    auto int8_s = sizeof(std::int8_t);
    // save current offset
    auto curr_offset = input_file.tellg();

    // set the offset to the given offset
    input_file.seekg(static_cast<std::streampos>(offset));

    utf16_size = read_uleb128();

    while (utf16_size-- > 0)
    {
        input_file.read(reinterpret_cast<char *>(&character), int8_s);
        new_str += static_cast<char>(character);
    }

    // return again
    input_file.seekg(curr_offset);
    return new_str;
}

std::string ShurikenStream::read_dex_string(std::int64_t offset) {
    std::string new_str = "";
    std::int8_t character = -1;
    std::uint64_t utf16_size;
    auto int8_s = sizeof(std::int8_t);
    // save current offset
    auto current_offset = input_file.tellg();

    utf16_size = read_uleb128();

    while (utf16_size--) {
        input_file.read(reinterpret_cast<char *>(&character), int8_s);
        new_str += static_cast<char>(character);
    }

    // return to offset
    input_file.seekg(current_offset, std::ios_base::beg);
    // return the new string
    return new_str;
}