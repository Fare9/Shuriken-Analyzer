//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file classes.cpp

#include "shuriken/parser/Dex/dex_classes.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

void ClassDataItem::parse_class_data_item(common::ShurikenStream &stream,
                                          DexFields &fields,
                                          DexMethods &methods,
                                          DexTypes &types) {
    auto current_offset = stream.tellg();

    std::uint64_t I;
    // IDs for the different variables
    std::uint64_t static_field = 0, instance_field = 0, direct_method = 0, virtual_method = 0;
    std::uint64_t access_flags;// access flags of the variables
    std::uint64_t code_offset; // offset for parsing

    log(LEVEL::MYDEBUG, "Started parsing a class data item");

    // read the sizes of the different variables
    std::uint64_t const static_fields_size = stream.read_uleb128();
    std::uint64_t const instance_fields_size = stream.read_uleb128();
    std::uint64_t const direct_methods_size = stream.read_uleb128();
    std::uint64_t const virtual_methods_size = stream.read_uleb128();

    for (I = 0; I < static_fields_size; ++I) {
        //! value needs to be incremented with the
        //! uleb128 read, so we always have that
        //! static_field = prev + uleb128
        static_field += stream.read_uleb128();
        //! now read the access flags
        access_flags = stream.read_uleb128();
        //! create the static field
        static_fields.push_back(std::make_unique<EncodedField>(fields.get_field_by_id(static_cast<uint32_t>(static_field)),
                                                               static_cast<shuriken::dex::TYPES::access_flags>(access_flags)));
    }

    for (I = 0; I < instance_fields_size; ++I) {
        instance_field += stream.read_uleb128();
        access_flags = stream.read_uleb128();
        instance_fields.push_back(std::make_unique<EncodedField>(fields.get_field_by_id(static_cast<uint32_t>(instance_field)),
                                                                 static_cast<shuriken::dex::TYPES::access_flags>(access_flags)));
    }

    for (I = 0; I < direct_methods_size; ++I) {
        direct_method += stream.read_uleb128();
        access_flags = stream.read_uleb128();
        // for the code item
        code_offset = stream.read_uleb128();
        direct_methods.push_back(std::make_unique<EncodedMethod>(methods.get_method_by_id(static_cast<uint32_t>(direct_method)),
                                                                 static_cast<shuriken::dex::TYPES::access_flags>(access_flags)));
        direct_methods.back()->parse_encoded_method(stream, code_offset, types);
    }

    for (I = 0; I < virtual_methods_size; ++I) {
        virtual_method += stream.read_uleb128();
        access_flags = stream.read_uleb128();
        code_offset = stream.read_uleb128();
        virtual_methods.push_back(std::make_unique<EncodedMethod>(methods.get_method_by_id(static_cast<uint32_t>(virtual_method)),
                                                                  static_cast<shuriken::dex::TYPES::access_flags>(access_flags)));
        virtual_methods.back()->parse_encoded_method(stream, code_offset, types);
    }

    log(LEVEL::MYDEBUG, "Finished parsing a class data item");

    stream.seekg(current_offset, std::ios_base::beg);
}

std::size_t ClassDataItem::get_number_of_static_fields() const {
    return static_fields.size();
}

std::size_t ClassDataItem::get_number_of_instance_fields() const {
    return instance_fields.size();
}

std::size_t ClassDataItem::get_number_of_direct_methods() const {
    return direct_methods.size();
}

std::size_t ClassDataItem::get_number_of_virtual_methods() const {
    return virtual_methods.size();
}

EncodedField *ClassDataItem::get_static_field_by_id(std::uint32_t id) {
    if (id >= static_fields.size())
        throw std::runtime_error("Error id value given incorrect");

    return static_fields[id].get();
}

EncodedField *ClassDataItem::get_instance_field_by_id(std::uint32_t id) {
    if (id >= instance_fields.size())
        throw std::runtime_error("Error id value given incorrect");
    return instance_fields[id].get();
}

EncodedMethod *ClassDataItem::get_direct_method_by_id(std::uint32_t id) {
    if (id >= direct_methods.size())
        throw std::runtime_error("Error id value given incorrect");
    return direct_methods[id].get();
}

EncodedMethod *ClassDataItem::get_virtual_method_by_id(std::uint32_t id) {
    if (id >= virtual_methods.size())
        throw std::runtime_error("Error id value given incorrect");
    return virtual_methods[id].get();
}

ClassDataItem::it_encoded_fields ClassDataItem::get_static_fields() {
    auto &aux = get_static_fields_vector();
    return deref_iterator_range(aux);
}

ClassDataItem::encoded_fields_s_t &ClassDataItem::get_static_fields_vector() {
    if (static_fields_s.empty() || static_fields_s.size() != static_fields.size()) {
        static_fields_s.clear();
        for (const auto &entry: static_fields)
            static_fields_s.push_back(std::ref(*entry));
    }
    return static_fields_s;
}

ClassDataItem::it_encoded_fields ClassDataItem::get_instance_fields() {
    auto &aux = get_instance_fields_vector();
    return deref_iterator_range(aux);
}

ClassDataItem::encoded_fields_s_t &ClassDataItem::get_instance_fields_vector() {
    if (instance_fields_s.empty() || instance_fields.size() != instance_fields_s.size()) {
        instance_fields_s.clear();
        for (const auto &entry: instance_fields)
            instance_fields_s.push_back(std::ref(*entry));
    }
    return instance_fields_s;
}

ClassDataItem::it_encoded_method ClassDataItem::get_direct_methods() {
    auto &aux = get_direct_methods_vector();
    return deref_iterator_range(aux);
}

ClassDataItem::encoded_methods_s_t &ClassDataItem::get_direct_methods_vector() {
    if (direct_methods_s.empty() || direct_methods_s.size() != direct_methods.size()) {
        direct_methods_s.clear();
        for (const auto &entry: direct_methods)
            direct_methods_s.push_back(std::ref(*entry));
    }
    return direct_methods_s;
}

ClassDataItem::it_encoded_method ClassDataItem::get_virtual_methods() {
    auto &aux = get_virtual_methods_s();
    return deref_iterator_range(aux);
}

ClassDataItem::encoded_methods_s_t &ClassDataItem::get_virtual_methods_s() {
    if (virtual_methods_s.empty() || virtual_methods_s.size() != virtual_methods.size()) {
        virtual_methods_s.clear();
        for (const auto &entry: virtual_methods)
            virtual_methods_s.push_back(std::ref(*entry));
    }
    return virtual_methods_s;
}

void ClassDef::parse_class_def(common::ShurikenStream &stream,
                               DexStrings &strings,
                               DexTypes &types,
                               DexFields &fields,
                               DexMethods &methods) {
    auto current_offset = stream.tellg();
    size_t I;
    std::uint32_t size;
    std::uint16_t idx;

    log(LEVEL::MYDEBUG, "Starting parsing a class def");

    // first read the classdefstruct_t
    stream.read_data<classdefstruct_t>(classdefstruct, sizeof(classdefstruct_t));
    // assign the class idx to the current class
    class_idx = reinterpret_cast<DVMClass *>(types.get_type_by_id(classdefstruct.class_idx));

    // assign the super class
    if (classdefstruct.superclass_idx != shuriken::dex::NO_INDEX)
        superclass_idx = reinterpret_cast<DVMClass *>(types.get_type_by_id(classdefstruct.superclass_idx));

    // assign the source file
    if (classdefstruct.source_file_idx != shuriken::dex::NO_INDEX)
        source_file = strings.get_string_by_id(classdefstruct.source_file_idx);

    // Start parsing the interfaces
    if (classdefstruct.interfaces_off) {
        stream.seekg(classdefstruct.interfaces_off, std::ios_base::beg);

        stream.read_data<std::uint32_t>(size, sizeof(std::uint32_t));

        for (I = 0; I < size; ++I) {
            stream.read_data<std::uint16_t>(idx, sizeof(std::uint16_t));
            interfaces.push_back(
                    reinterpret_cast<DVMClass *>(types.get_type_by_id(idx)));
        }
    }

    // Parse the annotations
    if (classdefstruct.annotations_off) {
        stream.seekg(classdefstruct.annotations_off, std::ios_base::beg);
        annotation_directory.parse_annotation_directory_item(stream);
    }

    // parse the class data
    if (classdefstruct.class_data_off) {
        stream.seekg(classdefstruct.class_data_off, std::ios_base::beg);
        class_data_item.parse_class_data_item(stream, fields, methods, types);
    }

    // parse the static values
    if (classdefstruct.static_values_off) {
        stream.seekg(classdefstruct.static_values_off, std::ios_base::beg);
        static_values.parse_encoded_array(stream, types, strings);
    }


    log(LEVEL::MYDEBUG, "Finished parsing a class def");

    stream.seekg(current_offset, std::ios_base::beg);
}

const ClassDef::classdefstruct_t &ClassDef::get_class_def_struct() const {
    return classdefstruct;
}

ClassDef::classdefstruct_t &ClassDef::get_class_def_struct() {
    return classdefstruct;
}

DVMClass *ClassDef::get_class_idx() {
    return class_idx;
}


shuriken::dex::TYPES::access_flags ClassDef::get_access_flags() const {
    return static_cast<
            shuriken::dex::TYPES::access_flags>(classdefstruct.access_flags);
}

DVMClass *ClassDef::get_superclass() {
    return superclass_idx;
}

std::string_view ClassDef::get_source_file() {
    return source_file;
}

ClassDef::it_interfaces_list ClassDef::get_interfaces() {
    return make_range(interfaces.begin(), interfaces.end());
}

const ClassDataItem &ClassDef::get_class_data_item() const {
    return class_data_item;
}

ClassDataItem &ClassDef::get_class_data_item() {
    return class_data_item;
}

const EncodedArray &ClassDef::get_static_values() const {
    return static_values;
}

EncodedArray &ClassDef::get_static_values() {
    return static_values;
}

void DexClasses::parse_classes(common::ShurikenStream &stream,
                               std::uint32_t number_of_classes,
                               std::uint32_t offset,
                               DexStrings &strings,
                               DexTypes &types,
                               DexFields &fields,
                               DexMethods &methods) {
    auto current_offset = stream.tellg();
    std::unique_ptr<ClassDef> classdef;
    size_t I;

    log(LEVEL::INFO, "Started parsing classes");

    // go to the offset
    stream.seekg(offset, std::ios_base::beg);

    for (I = 0; I < number_of_classes; ++I) {
        classdef = std::make_unique<ClassDef>();
        classdef->parse_class_def(stream, strings, types, fields, methods);
        class_defs.push_back(std::move(classdef));
        // since classdef restore the pointer it found, move it to next
        // structure
        stream.seekg(sizeof(ClassDef::classdefstruct_t), std::ios_base::cur);
    }

    log(LEVEL::INFO, "Finished parsing classes");

    stream.seekg(current_offset, std::ios_base::beg);
}

DexClasses::it_class_defs DexClasses::get_classdefs() {
    auto &aux = get_classdefs_vector();
    return deref_iterator_range(aux);
}

DexClasses::class_defs_s_t &DexClasses::get_classdefs_vector() {
    if (class_defs_s.empty() || class_defs_s.size() != class_defs.size()) {
        class_defs_s.clear();
        for (const auto &entry: class_defs)
            class_defs_s.push_back(std::ref(*entry));
    }
    return class_defs_s;
}