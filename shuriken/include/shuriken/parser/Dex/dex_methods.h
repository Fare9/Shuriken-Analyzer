//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file methods.h
// @brief Store information about the mehods in the DEX file

#ifndef SHURIKENLIB_DEX_METHODS_H
#define SHURIKENLIB_DEX_METHODS_H

#include "shuriken/parser/Dex/dex_protos.h"
#include "shuriken/parser/Dex/dex_strings.h"
#include "shuriken/parser/Dex/dex_types.h"

#include <memory>
#include <string_view>
#include <vector>

namespace shuriken {
    namespace parser {
        namespace dex {
            class MethodID {
                /// @brief Class which method belongs to
                DVMType *class_;
                /// @brief Prototype of the current method
                ProtoID *protoId;
                /// @brief Name of the method
                std::string_view name;
                /// @brief Pretty name of the method with the prototype
                std::string demangled_name;
                /// @brief Name in the dalvik format
                std::string dalvik_name;

            public:
                /// @brief Constructor of the MethodID
                /// @param class_ class of the method
                /// @param return_type type returned by prototype of the method
                /// @param name_ name of the method
                MethodID(DVMType *class_, ProtoID *protoId, std::string_view name) : class_(class_), protoId(protoId), name(name) {}

                /// @brief Destructor of MethodID, default constructor
                ~MethodID() = default;

                const DVMType *get_class() const;

                DVMType *get_class();

                const ProtoID *get_prototype() const;

                ProtoID *get_prototype();

                std::string_view get_method_name();

                std::string_view demangle();

                std::string_view dalvik_name_format();
            };

            class DexMethods {
            public:
                using method_ids_t = std::vector<std::unique_ptr<MethodID>>;
                using it_methods = iterator_range<method_ids_t::iterator>;
                using it_const_methods = iterator_range<const method_ids_t::iterator>;

            private:
                /// @brief List of methods from the DEX file
                method_ids_t method_ids;

            public:
                /// @brief Constructor of DexMethods, default Constructor
                DexMethods() = default;

                /// @bief Destructor of DexMethods, default Destructor
                ~DexMethods() = default;

                /// @brief Parse all the method ids objects.
                /// @param stream stream with the dex file
                /// @param types types objects
                /// @param strings strings objects
                /// @param methods_offset offset to the ids of the methods
                /// @param methods_size number of methods to read
                void parse_methods(
                        common::ShurikenStream &stream,
                        DexTypes &types,
                        DexProtos &protos,
                        DexStrings &strings,
                        std::uint32_t methods_offset,
                        std::uint32_t methods_size);

                /// @brief Get an iterator for going through the methods from the DEX file
                /// @return iterator with the methods
                it_methods get_methods();

                /// @brief Get a constant iterator for going through the methods from the DEX file
                /// @return constant iterator with the methods
                it_const_methods get_methods_const();

                /// @brief Get the number of methods from the DEX file
                /// @return number of methods
                size_t get_number_of_methods() const;

                /// @brief Get the MethodID pointer of the provided id.
                /// @param id id of the method to retrieve
                /// @return MethodID object
                MethodID *get_method_by_id(std::uint32_t id);

                /// @brief Dump the content of the methods as XML
                void to_xml(std::ofstream &fos);
            };
        }// namespace dex
    }    // namespace parser
}// namespace shuriken

#endif//SHURIKENLIB_DEX_METHODS_H
