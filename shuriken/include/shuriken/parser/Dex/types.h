//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file types.h
// @brief Manager of Types for Dalvik

#ifndef SHURIKENLIB_TYPES_H
#define SHURIKENLIB_TYPES_H

#include "shuriken/common/shurikenstream.h"
#include "shuriken/parser/Dex/strings.h"
#include <iostream>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <memory>
#include <algorithm>

namespace shuriken {
    namespace parser {
        namespace dex {
            /// @brief Types of the DVM we have by default fundamental,
            /// classes and array Types
            enum type_e
            {
                FUNDAMENTAL,    //! fundamental type (int, float...)
                CLASS,          //! user defined class
                ARRAY,          //! an array type
                UNKNOWN         //! maybe wrong?
            };

            /// @brief enum with the fundamental Types
            enum fundamental_e
            {
                BOOLEAN,
                BYTE,
                CHAR,
                DOUBLE,
                FLOAT,
                INT,
                LONG,
                SHORT,
                VOID
            };

            const std::unordered_map<fundamental_e, std::string> fundamental_s =
            {
                    {BOOLEAN, "boolean"},
                    {BYTE, "byte"},
                    {CHAR, "char"},
                    {DOUBLE, "double"},
                    {FLOAT, "float"},
                    {INT, "int"},
                    {LONG, "long"},
                    {SHORT, "short"},
                    {VOID, "void"}
            };

            class DVMType {
            private:
                /// @brief what type is it?
                enum type_e type;
                /// @brief string with the type in raw
                std::string_view raw_type;
            public:
                /// @brief Constructor of DVMType
                /// @param type the type to overload
                /// @param raw_type string with the type in raw
                DVMType(type_e type, std::string_view raw_type)
                        : type(type), raw_type(raw_type)
                {}

                /// @brief Destructor of DVMType
                virtual ~DVMType() = default;

                /// @brief Virtual method to return the type
                /// @return type of the variable
                virtual type_e get_type() const {
                    return type;
                }

                /// @brief Get the raw type as a string_view
                /// @return raw type
                virtual std::string_view get_raw_type() const {
                    return raw_type;
                }

                /// @brief Get a beautified representation of the type
                /// @return beautified representation of the type
                virtual std::string print_type() = 0;
            };

            /// @brief Operator == for comparison between two DVMTypes
            inline bool operator==(const DVMType& lhs, const DVMType& rhs) {
                if ((lhs.get_type() == rhs.get_type()) && (lhs.get_raw_type() == rhs.get_raw_type()))
                    return true;
                return false;
            }
            /// @Brief Operator != for comparison between two DVMTypes
            inline bool operator!=(const DVMType& lhs, const DVMType& rhs) {
                return !(lhs == rhs);
            }

            class DVMFundamental : public DVMType
            {
            private:
                /// @brief what type of fundamental is?
                enum fundamental_e fundamental;
                /// @brief name of the fundamental type
                std::string_view name;
            public:
                /// @brief Constructor for fundamental Types, these are int, bool, char...
                /// @param fundamental the type of fundamental for the object (only one will exist for fundamental)
                /// @param raw_name string raw name for the fundamental type from the string table
                DVMFundamental(fundamental_e fundamental, std::string_view raw_name) :
                        DVMType(type_e::FUNDAMENTAL, raw_name),
                        fundamental(fundamental) {
                    if (!fundamental_s.contains(fundamental)) {
                        throw std::runtime_error("Error fundamental value provided doesn't exist");
                    }
                    name = std::string_view(fundamental_s.at(fundamental));
                }

                ~DVMFundamental() = default;

                std::string print_type() override {
                    return std::string(name);
                }

                /// @brief Get the name of the fundamental type as a string
                /// @return string_view with the name of the fundamental type
                std::string_view get_name() const {
                    return name;
                }

                /// @brief Get the enum with the fundamental type.
                /// @return value from enum `fundamental_e`
                fundamental_e get_fundamental_type() const {
                    return fundamental;
                }

            };

            class DVMClass : public DVMType {
            private:
                /// @brief name of the class in dot format
                std::string class_name;
                /// @brief read only format for the class
                std::string_view class_name_v;

            public:
                /// @brief Defines a class from Dalvik, here we will store it in canonical name
                /// @param raw_name name in format "Lclass/name;"
                DVMClass(std::string_view raw_name) :
                        DVMType(type_e::CLASS, raw_name) {
                    if (raw_name.empty() || raw_name.length() == 1)
                        std::runtime_error("Incorrect length for DVMClass");
                    if (!raw_name.starts_with('L') || !raw_name.ends_with(';'))
                        std::runtime_error("Incorrect class name");

                    class_name = raw_name.substr(1, raw_name.length()-2);
                    std::replace(class_name.begin(), class_name.end(), '/', '.');

                    class_name_v = std::string_view (class_name);
                }

                ~DVMClass() = default;

                std::string print_type() override {
                    return class_name;
                }

                std::string_view get_class_name() const {
                    return class_name_v;
                }
            };

            class DVMArray : public DVMType {
            private:
                std::string array_name;
                std::string_view array_name_v;
                /// @brief Depth of the array, it is possible to
                /// create arrays with different depth like [[C
                size_t depth;
                /// @brief type of the array
                std::unique_ptr<DVMType> array_type;
            public:
                /// @brief Constructor of DVMArrays, they have a depth of the array
                /// and a base type
                /// @param depth dimension of the array
                /// @param array_type base type of the array
                /// @param raw_name raw string of the array
                DVMArray(size_t depth,
                         std::unique_ptr<DVMType>& array_type,
                         std::string_view raw_name) :
                        DVMType(type_e::ARRAY, raw_name),
                        depth(depth), array_type(std::move(array_type)) {
                    array_name = this->array_type->print_type();
                    for (size_t I = 0; I < depth; ++I) array_name += "[]";
                    array_name_v = std::string_view(array_name);
                }

                ~DVMArray() = default;

                std::string print_type() override {
                    return array_name;
                }

                /// @brief get a string_view representation of an array string
                /// @return string_view of array
                std::string_view get_array_string() const {
                    return array_name_v;
                }

                /// @brief Get the depth of the array
                /// @return dimension of the array
                size_t get_array_depth() const {
                    return depth;
                }

                /// @brief Get the base type of the array as a pointer
                /// to DVMType
                /// @return constant pointer to DVMType
                const DVMType* get_array_base_type() const {
                    return array_type.get();
                }
            };

            class Unknown : public DVMType {
            public:
                /// @brief Constructor of unknown type
                /// @param type type to be stored in parent class
                /// @param raw raw
                Unknown(std::string_view raw) :
                        DVMType(type_e::UNKNOWN, raw)
                {}

                ~Unknown() = default;

                /// @brief Get Unknown type as a string
                /// @return UNKNOWN value as string
                std::string print_type() override
                {
                    return "Unknown";
                }
            };

            class Types {
            private:
                /// @brief Types from the Dalvik Virtual Machine
                std::vector<std::unique_ptr<DVMType>> ordered_types;

                /// @brief Parse the provided string and return a new DVMType
                /// @param name type to parse
                /// @return DVMType based on the string
                std::unique_ptr<DVMType> parse_type(std::string_view name);

            public:
                /// @brief Constructor of the Types object, nothing for initialization
                Types() = default;
                /// @brief Destructor of Types
                ~Types() = default;

                /// @brief Parse all the Types from the DVM
                /// @param shurikenStream stream where to read the DVM Types
                /// @param strings_ Strings to retrieve the raw name of the Types
                /// @param offset_types offset in the file where Types are
                /// @param n_of_types number of Types to read
                void parse_types(common::ShurikenStream& shurikenStream,
                                 Strings& strings_,
                                 std::uint32_t offset_types,
                                 std::uint32_t n_of_types);

                /// @brief Get a constant pointer to a DVMType by id
                /// @param id order of the type
                /// @return constant pointer to a DVMType
                const DVMType* get_type_by_id_const(std::uint32_t id) const {
                    if (id >= ordered_types.size()) {
                        throw std::runtime_error("Error id for type provided is incorrect");
                    }

                    return ordered_types.at(id).get();
                }

                /// @brief Get a pointer to a DVMType by id
                /// @param id order of the type
                /// @return pointer to a DVMTypeLjava/lang/Object;
                DVMType* get_type_by_id(std::uint32_t id) {
                    if (id >= ordered_types.size()) {
                        throw std::runtime_error("Error id for type provided is incorrect");
                    }

                    return ordered_types.at(id).get();
                }

                /// @brief Get the ID from the given type as parameter
                /// @param type type to look for the id
                /// @return ID from the given type
                std::int64_t get_id_by_type(DVMType * type) {
                    auto it = std::ranges::find_if(ordered_types,
                                                   [&](const std::unique_ptr<DVMType>& t) {
                        return *type == *t;
                    });

                    if (it == ordered_types.end())
                        return -1;

                    return std::distance(ordered_types.begin(), it);
                }

                /// @brief Dump the content of the Types to an XML file
                /// @param fos XML file where to dump the content
                void to_xml(std::ofstream &fos);
            };
        }
    }
}

#endif //SHURIKENLIB_TYPES_H
