//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file classes.h
// @brief This is an important file, since classes manage all the magic
// behind the DEX files. DexClasses will contain all the encoded data
// (methods, fields, etc), as well as all the information about them
// two DexClasses are important here: `ClassDefsStruct` and `ClassDataItem`.
// `ClassDefsStruct` contains ids and offsets of the other information.
// while `ClassDataItem` contains all the items.

#ifndef SHURIKENLIB_DEX_CLASSES_H
#define SHURIKENLIB_DEX_CLASSES_H

#include "shuriken/parser/Dex/dex_annotations.h"
#include "shuriken/parser/Dex/dex_encoded.h"

#include <iostream>
#include <unordered_map>
#include <vector>

namespace shuriken {
    namespace parser {
        namespace dex {
            class ClassDataItem {
            public:
                using encoded_fields_t = std::vector<std::unique_ptr<EncodedField>>;
                using it_encoded_fields = iterator_range<encoded_fields_t::iterator>;

                using encoded_methods_t = std::vector<std::unique_ptr<EncodedMethod>>;
                using it_encoded_method = iterator_range<encoded_methods_t::iterator>;

            private:
                /// @brief Static fields from the class
                encoded_fields_t static_fields;

                /// @brief Instance fields from the class
                encoded_fields_t instance_fields;

                /// @brief Direct methods from the class
                encoded_methods_t direct_methods;

                /// @brief Virtual methods from the class
                encoded_methods_t virtual_methods;

            public:
                /// @brief Constructor of ClassDataItem
                ClassDataItem() = default;
                /// @brief Destructor of ClassDataItem
                ~ClassDataItem() = default;

                /// @brief Method to parse the ClassDataItem
                /// @param stream stream DEX file
                /// @param fields fields of the DEX file
                /// @param methods methods of the DEX file
                /// @param types types of the DEX file
                void parse_class_data_item(common::ShurikenStream &stream,
                                           DexFields &fields,
                                           DexMethods &methods,
                                           DexTypes &types);

                /// @brief Get the number of the static fields
                /// @return size of static fields
                std::size_t get_number_of_static_fields() const;

                /// @brief Get number of instance fields
                /// @return size of instance fields
                std::size_t get_number_of_instance_fields() const;

                /// @brief Get number of direct methods
                /// @return size of direct methods
                std::size_t get_number_of_direct_methods() const;

                /// @brief Get number of virtual methods
                /// @return size of virtual methods
                std::size_t get_number_of_virtual_methods() const;

                /// @brief Get a pointer to static field by the id of the FieldID
                /// @param id id of the FieldID
                /// @return pointer to static encodedfield
                EncodedField *get_static_field_by_id(std::uint32_t id);

                /// @brief Get an instance field by the id of the FieldID
                /// @param id id of the FieldID
                /// @return pointer to instance encodedfield
                EncodedField *get_instance_field_by_id(std::uint32_t id);

                /// @brief Get a direct method by the id of the MethodID
                /// @param id id of the MethodID
                /// @return pointer to direct encodedmethod
                EncodedMethod *get_direct_method_by_id(std::uint32_t id);

                /// @brief Get a virtual method by the id of the MethodID
                /// @param id id of the MethodID
                /// @return pointer to virtual encodedmethod
                EncodedMethod *get_virtual_method_by_id(std::uint32_t id);

                /// @brief Get all the static fields from the class
                /// @return iterator to static fields
                it_encoded_fields get_static_fields();

                /// @brief Get all the instance fields from the class
                /// @return iterator to instance fields
                it_encoded_fields get_instance_fields();

                /// @brief Get all the direct methods from the class
                /// @return iterator to direct methods
                it_encoded_method get_direct_methods();

                it_encoded_method get_virtual_methods();
            };

            /// @brief Definition of class with all the ids and offsets
            /// for all the other data
            class ClassDef {
            public:
#pragma pack(1)
                /// @brief Definition of offsets and IDs
                struct classdefstruct_t {
                    std::uint32_t class_idx;        //! idx for the current class
                    std::uint32_t access_flags;     //! flags for this class
                    std::uint32_t superclass_idx;   //! parent class id
                    std::uint32_t interfaces_off;   //! interfaces implemented by class
                    std::uint32_t source_file_idx;  //! idx to a string with source file
                    std::uint32_t annotations_off;  //! debugging information and other data
                    std::uint32_t class_data_off;   //! offset to class data item
                    std::uint32_t static_values_off;//! offset to static values
                };
#pragma pack()
                using interfaces_list_t = std::vector<DVMClass *>;
                using it_interfaces_list = iterator_range<interfaces_list_t::iterator>;

            private:
                /// @brief Structure with the definition of the class
                classdefstruct_t classdefstruct;
                /// @brief DVMClass for the current class
                DVMClass *class_idx;
                /// @brief DVMClass for the parent/super class
                DVMClass *superclass_idx;
                /// @brief String with the source file
                std::string_view source_file;
                /// @brief vector with the interfaces implemented
                interfaces_list_t interfaces;
                /// @brief Annotations of the class
                AnnotationDirectoryItem annotation_directory;
                /// @brief ClassDataItem value fo the current class
                ClassDataItem class_data_item;
                /// @brief Array of initial values for static fields.
                EncodedArray static_values;

            public:
                /// @brief Constructor of ClassDef
                ClassDef() = default;
                /// @brief Destructor of ClassDef
                ~ClassDef() = default;

                /// @brief Parse the current ClassDef for that we will parse the
                /// classdef_t structure, and then all the other fields.
                /// @param stream stream with DEX file currently parsed
                /// @param strings strings of the DEX file
                /// @param types types of the DEX file
                /// @param fields fields of the DEX file
                /// @param methods methods of the DEX file
                void parse_class_def(common::ShurikenStream &stream,
                                     DexStrings &strings,
                                     DexTypes &types,
                                     DexFields &fields,
                                     DexMethods &methods);

                /// @brief Get a constant reference to the classdefstruct_t
                /// of the class, this structure contains information about
                /// the class
                /// @return constant reference to classdefstruct_t structure
                const classdefstruct_t &get_class_def_struct() const;

                /// @brief Get a reference to the classdefstruct_t
                /// of the class, this structure contains information about
                /// the class
                /// @return reference to classdefstruct_t structure
                classdefstruct_t &get_class_def_struct();

                /// @brief Get a pointer to the DVMClass of the current class
                /// @return pointer to DVMClass of current class
                DVMClass *get_class_idx();

                shuriken::dex::TYPES::access_flags get_access_flags() const;

                /// @brief Get a pointer to the DVMClass of
                /// the super class of the current one
                /// @return pointer to DVMClass of the super class
                DVMClass *get_superclass();

                /// @brief Get a string_view to the string with the source file
                /// @return string_view to source file string
                std::string_view get_source_file();

                /// @brief Get an iterator to the interfaces implemented by the class
                /// @return interfaces implemented
                it_interfaces_list get_interfaces();

                /// @brief Get a constant reference to the class data item
                /// @return constant reference to the class data item
                const ClassDataItem &get_class_data_item() const;

                /// @brief Get a reference to the class data item
                /// @return reference to the class data item
                ClassDataItem &get_class_data_item();

                /// @brief Return a constant reference to the encoded array
                /// @return static values as encoded array
                const EncodedArray &get_static_values() const;

                /// @brief Return a reference to the encoded array
                /// @return static values as encoded array
                EncodedArray &get_static_values();
            };

            /// @brief All classes from the DEX files
            class DexClasses {
            public:
                using class_defs_t = std::vector<std::unique_ptr<ClassDef>>;
                using it_class_defs = iterator_range<class_defs_t::iterator>;

            private:
                /// @brief All the class_defs from the DEX, one
                /// for each class
                class_defs_t class_defs;

            public:
                /// @brief Constructor from DexClasses
                DexClasses() = default;
                /// @brief Destructor from DexClasses
                ~DexClasses() = default;
                /// @brief Parse all the classes from the DEX files
                /// @param stream stream with the DEX file
                /// @param number_of_classes number of classes from the DEX
                /// @param offset offset to parse the classes
                /// @param strings strings from the DEX file
                /// @param types types from the DEX file
                /// @param fields fields from the DEX file
                /// @param methods methods from the DEX file
                void parse_classes(common::ShurikenStream &stream,
                                   std::uint32_t number_of_classes,
                                   std::uint32_t offset,
                                   DexStrings &strings,
                                   DexTypes &types,
                                   DexFields &fields,
                                   DexMethods &methods);

                /// @brief Get an iterator to the classdefs objects
                /// @return class def objects from the DEX file
                it_class_defs get_classdefs();
            };
        }// namespace dex
    }    // namespace parser
}// namespace shuriken

#endif//SHURIKENLIB_DEX_CLASSES_H
