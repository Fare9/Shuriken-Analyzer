//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file classes.cpp

#include "shuriken/parser/Dex/classes.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

void ClassDataItem::parse_class_data_item(common::ShurikenStream& stream,
                           Fields& fields,
                           Methods& methods,
                           Types& types) {
    auto current_offset = stream.tellg();
    auto my_logger = shuriken::logger();

    std::uint64_t I;
    // IDs for the different variables
    std::uint64_t static_field = 0, instance_field = 0, direct_method = 0, virtual_method = 0;
    std::uint64_t access_flags; // access flags of the variables
    std::uint64_t code_offset; // offset for parsing

    my_logger->debug("Started parsing a class data item");

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
        static_fields[static_field] =
                std::make_unique<EncodedField>(fields.get_field_by_id(static_field),
                                                                          static_cast<shuriken::dex::TYPES::access_flags>(access_flags));

    }

    for (I = 0; I < instance_fields_size; ++I) {
        instance_field += stream.read_uleb128();
        access_flags += stream.read_uleb128();
        instance_fields[instance_field] =
                std::make_unique<EncodedField>(fields.get_field_by_id(static_field),
                                               static_cast<shuriken::dex::TYPES::access_flags>(access_flags));
    }

    for (I = 0; I < direct_methods_size; ++I) {
        direct_method += stream.read_uleb128();
        access_flags = stream.read_uleb128();
        // for the code item
        code_offset = stream.read_uleb128();
        direct_methods[direct_method] =
                std::make_unique<EncodedMethod>(methods.get_method_by_id(direct_method),
                                                static_cast<shuriken::dex::TYPES::access_flags>(access_flags));
        direct_methods[direct_method]->parse_encoded_method(stream, code_offset, types);
    }

    for (I = 0; I < virtual_methods_size; ++I) {
        virtual_method += stream.read_uleb128();
        access_flags = stream.read_uleb128();
        code_offset = stream.read_uleb128();
        virtual_methods[virtual_method] = std::make_unique<EncodedMethod>(methods.get_method_by_id(direct_method),
                                                                          static_cast<shuriken::dex::TYPES::access_flags>(access_flags));
        virtual_methods[virtual_method]->parse_encoded_method(stream, code_offset, types);
    }

    my_logger->debug("Finished parsing a class data item");

    stream.seekg(current_offset, std::ios_base::beg);
}

void ClassDef::parse_class_def(common::ShurikenStream& stream,
                     Strings& strings,
                     Types& types,
                     Fields& fields,
                     Methods& methods) {
    auto current_offset = stream.tellg();
    auto my_logger = shuriken::logger();
    size_t I;
    std::uint32_t size;
    std::uint16_t idx;

    my_logger->debug("Starting parsing a class def");

    // first read the classdefstruct_t
    stream.read_data<classdefstruct_t>(classdefstruct, sizeof(classdefstruct_t));
    // assign the class idx to the current class
    class_idx = reinterpret_cast<DVMClass*>(types.get_type_by_id(classdefstruct.class_idx));

    // assign the super class
    if (classdefstruct.superclass_idx != shuriken::dex::NO_INDEX)
        superclass_idx = reinterpret_cast<DVMClass*>(types.get_type_by_id(classdefstruct.superclass_idx));

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
                    reinterpret_cast<DVMClass*>(types.get_type_by_id(idx)));
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


    my_logger->debug("Finished parsing a class def");

    stream.seekg(current_offset, std::ios_base::beg);
}

void Classes::parse_classes(common::ShurikenStream& stream,
                   std::uint32_t number_of_classes,
                   std::uint32_t offset,
                   Strings& strings,
                   Types& types,
                   Fields& fields,
                   Methods& methods) {
    auto current_offset = stream.tellg();
    auto my_logger = shuriken::logger();
    std::unique_ptr<ClassDef> classdef;
    size_t I;

    my_logger->info("Started parsing classes");

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

    my_logger->info("Finished parsing classes");

    stream.seekg(current_offset, std::ios_base::beg);
}