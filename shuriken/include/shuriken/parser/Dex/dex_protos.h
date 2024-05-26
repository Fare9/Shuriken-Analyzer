//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file protos.h
// @brief Manage all the prototypes used in a DEX file, the prototypes
// include parameters return types, etc.

/*
 * Each proto structure is:
 *  ProtoID {
 *      uint shorty_idx, # OFFSET to a string with return type
 *      uint return_type_idx, # OFFSET to a type which points to string with return type
 *      uint parameters_off # ---------| Offset to parameters in type list type
 *  }                                  |
 *                                     |
 *  ------------------------------------
 *  |
 *  v
 *  type_list {
 *      uint size, # Size of the list in entries
 *      list type_item[size] # ---------|
 *  }                                   |
 *                                      |
 *  -------------------------------------
 *  |
 *  v
 *  type_item {
 *      ushort type_idx # type_idx of each member
 *  }
 *
 *  ProtoID[] protos
 */

#ifndef SHURIKEN_ANALYZER_PROTOS_H
#define SHURIKEN_ANALYZER_PROTOS_H

#include "shuriken/common/iterator_range.h"
#include "shuriken/common/shurikenstream.h"
#include "shuriken/parser/Dex/dex_types.h"
#include <iostream>
#include <string_view>
#include <vector>

namespace shuriken {
    namespace parser {
        namespace dex {
            class ProtoID {
            public:
                using parameters_type_t = std::vector<DVMType *>;
                using it_params = iterator_range<parameters_type_t::iterator>;
                using it_const_params = iterator_range<const parameters_type_t::iterator>;

            private:
                /// @brief String with proto as a string
                std::string_view shorty_idx;
                /// @brief Return type by the prototype
                DVMType *return_type = nullptr;
                /// @brief Vector with all the parameter types
                parameters_type_t parameters;
                /// @brief string representation of the parameters + return type
                /// e.g. (II)I
                std::string prototypes_dalvik_representation;
                /// @brief Parse the parameters from the stream
                /// each parameter will contain one type id
                /// @param stream stream where to read the information
                /// @param types where to extract the information
                /// @param parameters_off offset where to read the parameters
                void parse_parameters(
                        common::ShurikenStream &stream,
                        DexTypes &types,
                        std::uint32_t parameters_off);

            public:
                ProtoID(
                        common::ShurikenStream &stream,
                        DexTypes &types,
                        std::string_view shorty_idx,
                        std::uint32_t return_type_idx,
                        std::uint32_t parameters_off);
                /// @brief Get the shorty_idx with a string version of the prototype
                /// @return string view of shorty idx
                std::string_view get_shorty_idx() const;

                /// @brief Get a constant reference to the return type
                /// @return constant reference to return type
                const DVMType *get_return_type() const;

                /// @brief Get a dalvik representation of the prototype
                /// @return dalvik representation of prototype
                std::string_view get_dalvik_prototype();

                /// @brief Get a reference to the return type
                /// @return reference to return type
                DVMType *get_return_type();

                it_params get_parameters();

                it_const_params get_parameters_const();
            };

            inline bool operator==(const ProtoID &lhs, const ProtoID &rhs) {
                if (lhs.get_shorty_idx() == rhs.get_shorty_idx())
                    return true;
                return false;
            }

            inline bool operator!=(const ProtoID &lhs, const ProtoID &rhs) {
                return !(lhs == rhs);
            }

            class DexProtos {
            public:
                using protos_id_t = std::vector<std::unique_ptr<ProtoID>>;
                using it_protos = iterator_range<protos_id_t::iterator>;
                using it_const_protos = iterator_range<const protos_id_t::iterator>;

            private:
                /// @brief Prototypes that are part of the DEX file
                protos_id_t protos;

            public:
                /// @brief Constructor of DexProtos, default constructor
                DexProtos() = default;

                /// @brief Destructor of DexProtos, default destructor
                ~DexProtos() = default;

                /// @brief Parse all the ProtoIDs from the file
                /// @param stream stream with dex file
                /// @param number_of_protos number of protos to read
                /// @param offset offset where to read the protos
                /// @param strings object with all the strings from the dex
                /// @param types object with all the types from the dex
                void parse_protos(common::ShurikenStream &stream,
                                  std::uint32_t number_of_protos,
                                  std::uint32_t offset,
                                  DexStrings &strings,
                                  DexTypes &types);

                it_protos get_protos();

                it_const_protos get_protos_const();

                ProtoID *get_proto_by_id(std::uint32_t id);

                std::int64_t get_id_by_proto(ProtoID *proto);

                size_t get_number_of_protos() const;

                void to_xml(std::ofstream &xml_file);
            };
        }// namespace dex
    }    // namespace parser
}// namespace shuriken

#endif//SHURIKEN_ANALYZER_PROTOS_H
