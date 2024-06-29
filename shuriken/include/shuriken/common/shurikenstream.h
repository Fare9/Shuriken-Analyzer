//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file shurikenstream.h
// @brief Manager of opened files useful for reading them correctly.

#ifndef SHURIKENLIB_SHURIKENSTREAM_H
#define SHURIKENLIB_SHURIKENSTREAM_H

#include <cassert>
#include <cstdint>
#include <fstream>

namespace shuriken::common {
    class ShurikenStream {
    private:
        /// @brief stream of file
        std::ifstream &input_file;

        /// @brief size of the file
        std::int64_t file_size;

        /// @brief Initialize private data
        void initialize();

    public:
        /// @brief Maximum size for ansii DexStrings, used for reading
        /// DexStrings in Dalvik
        const std::int32_t MAX_ANSII_STR_SIZE = 256;

        /// @brief Constructor of ShurikenStream
        ShurikenStream(std::ifstream &input_file);

        ~ShurikenStream() = default;

        /// @brief Get the current file size
        /// @return size of opened file
        std::size_t get_file_size() const;

        /// @brief Read data from the file to a buffer
        /// @tparam T type of buffer where to read the data
        /// @param buffer parameter of a buffer where to read the data from the file
        /// @param read_size size to read from the file
        template<typename T>
        void read_data(T &buffer, size_t read_size) {
            if (read_size < 0) {
                throw std::runtime_error("read_size cannot be lower than 0");
            }

            input_file.read(reinterpret_cast<char *>(&buffer), read_size);

            if (!input_file) {
                throw std::runtime_error("error reading data from input file");
            }
        }

        /// @brief Retrieve the pointer of the current position in the file
        /// @return current position in the file
        std::streampos tellg() const;

        /// @brief Move the pointer inside the file
        /// @param off offset where to move the pointer in the stream file
        /// @param dir direction where to move the pointer in the file
        void seekg(std::streamoff off, std::ios_base::seekdir dir);

        /// @brief Move the pointer inside the file, throw exception if offset is out of bound
        /// @param off offset where to move the pointer in the stream file
        /// @param dir direction where to move the pointer in the file
        void seekg_safe(std::streamoff off, std::ios_base::seekdir dir);

        /// @brief Read a number in uleb128 format.
        /// @return uint64_t with the number
        std::uint64_t read_uleb128();

        /// @brief Read a number in sleb128 format.
        /// @return int64_t with the number
        std::int64_t read_sleb128();

        /// @brief Read a string as an array of char finisheError, d in a 0 byte
        /// @param offset the offset in the file where to read the string
        /// @return string read
        std::string read_ansii_string(std::int64_t offset);

        /// @brief Read a dex string, these DexStrings start always with their size
        /// in uleb128 format.
        /// @param offset the offset in the file where to read the string
        /// @return string read
        std::string read_dex_string(std::int64_t offset);
    };
}// namespace shuriken::common

#endif// SHURIKENLIB_SHURIKENSTREAM_H
