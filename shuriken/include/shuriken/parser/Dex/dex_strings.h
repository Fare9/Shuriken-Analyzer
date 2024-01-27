//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file strings.h
// @brief DexStrings of a DEX file

#ifndef SHURIKENLIB_DEX_STRINGS_H
#define SHURIKENLIB_DEX_STRINGS_H

#include "shuriken/common/shurikenstream.h"
#include <vector>
#include <string>
#include <ranges>
#include <algorithm>
#include <string_view>

namespace shuriken {
    namespace parser {
        namespace dex {

            using dex_strings_t = std::vector<std::string>;

            using dex_strings_view_t = std::vector<std::string_view>;

            class DexStrings {
            private:
                /// @brief Vector with all the DexStrings from the dex file
                dex_strings_t dex_strings;
                /// @brief View of the previous DexStrings for quickly accessing them
                dex_strings_view_t  dex_strings_view;
            public:
                /// @brief Constructor of the class, default one
                DexStrings() = default;
                /// @brief Destructor of the class, default one
                ~DexStrings() = default;

                /// @brief Function to parse the DexStrings from the dex file
                /// @param shuriken_stream stream with the dex file
                /// @param strings_offset offset in the file where DexStrings are
                /// @param n_of_strings number of DexStrings to read
                void parse_strings(common::ShurikenStream& shuriken_stream,
                                   std::uint32_t strings_offset,
                                   std::uint32_t n_of_strings);

                /// @brief get an string_view by the id of the string (position in the list)
                /// @param str_id id of the string to retrieve
                /// @return a read-only version of the string
                std::string_view get_string_by_id(std::uint32_t str_id) const {
                    if (str_id >= dex_strings_view.size())
                        throw std::runtime_error("Error id of string out of bound");
                    return dex_strings_view.at(str_id);
                }

                /// @brief get the number of DexStrings from the dex file
                /// @return number of DexStrings
                size_t get_number_of_strings() const {
                    return dex_strings_view.size();
                }

                /// @brief Get the id from an string_view
                /// @param str string to look for in DexStrings
                /// @return id from the string or -1 if not found
                std::int64_t get_id_by_string(std::string_view str) const {
                    auto it = std::ranges::find(dex_strings_view, str);

                    if (it == dex_strings_view.end())
                        return -1;

                    return std::distance(dex_strings_view.begin(), it);
                }

                std::uint32_t add_string(std::string str) {
                    // check if the string is already in the table
                    auto value = get_id_by_string(str);
                    if (value != -1)
                        return static_cast<std::uint32_t>(value);
                    // if it doesn´t exist, add it and return the id
                    dex_strings.push_back(str);
                    dex_strings_view.push_back(dex_strings.back());
                    return (dex_strings.size()-1);
                }

                /// @brief Dump the content of the DexStrings to an XML file
                /// @param fos XML file where to dump the content
                void to_xml(std::ofstream &fos);

                void dump_binary(std::ofstream &fos, std::int64_t offset);
            };

        }
    }
}

#endif //SHURIKENLIB_DEX_STRINGS_H
