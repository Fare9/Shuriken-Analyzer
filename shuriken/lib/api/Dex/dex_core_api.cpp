//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_core_api.cpp
// @brief Implements the necessary functions for the DEX part of
// the core api to work

#include "shuriken/api/shuriken_parsers_core.h"
#include "shuriken/parser/shuriken_parsers.h"

#include <vector>

namespace {

    const int TAG = 'SKEN';

    typedef struct {
        /// @brief tag to check that the provided structure is correct
        int tag;
        /// @brief DEX parser from shuriken
        shuriken::parser::dex::Parser * parser;
        /// @brief number of classes
        std::uint16_t number_of_classes;
        /// @brief classes created from DEX information
        hdvmclass_t * classes;
        /// @brief all the methods from the DEX (to access all the methods)
        std::vector<hdvmmethod_t*> methods;
    } dex_opaque_struct_t;

    void fill_dex_method(shuriken::parser::dex::EncodedMethod * encoded_method, hdvmmethod_t * method) {
        const auto method_id = encoded_method -> getMethodID();

        method -> method_name = method_id -> get_method_name().data();
        method -> prototype = method_id -> get_prototype() -> get_shorty_idx().data();
        method -> access_flags = encoded_method -> get_flags();
        method -> code_size = encoded_method -> get_code_item() -> get_bytecode().size();
        method -> code = encoded_method -> get_code_item() -> get_bytecode().data();
        method -> dalvik_name = encoded_method -> getMethodID() -> dalvik_name_format().data();
        method -> demangled_name = encoded_method -> getMethodID() -> demangle().data();
    }

    void fill_dex_field(shuriken::parser::dex::EncodedField * encoded_field, hdvmfield_t * field) {
        auto field_id = encoded_field -> get_field();
        auto field_type = field_id->field_type();

        field -> name = field_id -> field_name().data();
        field -> access_flags = encoded_field -> get_flags();
        field -> type_value = field_id -> field_type() -> get_raw_type().data();
        field -> fundamental_value = NONE;

        auto type = field_type -> get_type();

        if (type == shuriken::parser::dex::FUNDAMENTAL) {
            field -> type = FUNDAMENTAL;
            auto fundamental = dynamic_cast < shuriken::parser::dex::DVMFundamental * > (field_type);
            field -> fundamental_value = static_cast < hfundamental_e > (fundamental -> get_fundamental_type());
        } else if (type == shuriken::parser::dex::CLASS) {
            field->type = CLASS;
        } else if (type == shuriken::parser::dex::ARRAY) {
            field -> type = ARRAY;
            auto array = reinterpret_cast < shuriken::parser::dex::DVMArray * > (field_type);
            if (array -> get_array_base_type() -> get_type() == shuriken::parser::dex::FUNDAMENTAL) {
                const auto fundamental = reinterpret_cast <
                        const shuriken::parser::dex::DVMFundamental * > (array -> get_array_base_type());
                field -> fundamental_value = static_cast < hfundamental_e > (fundamental -> get_fundamental_type());
            }
        } else {
            throw std::runtime_error("Error, not supported type...");
        }
    }

    void fill_dex_opaque_struct(shuriken::parser::dex::Parser * parser, dex_opaque_struct_t * opaque_struct) {
        if (parser == nullptr || opaque_struct == nullptr)
            return;
        opaque_struct -> tag = TAG;
        opaque_struct -> parser = parser;
        opaque_struct -> number_of_classes = parser -> get_header().get_dex_header_const().class_defs_size;
        opaque_struct -> classes = (hdvmclass_t * ) malloc(opaque_struct -> number_of_classes * sizeof(hdvmclass_t));
        size_t i = 0;

        auto & classes = parser -> get_classes();

        for (auto & class_def: classes.get_classdefs()) {
            auto class_idx = class_def -> get_class_idx();
            auto super_class = class_def -> get_superclass();
            auto & class_data_item = class_def -> get_class_data_item();
            auto new_class = & opaque_struct -> classes[i++];

            new_class -> class_name = class_idx -> get_class_name().data();
            if (super_class)
                new_class -> super_class = super_class -> get_class_name().data();
            if (!class_def -> get_source_file().empty())
                new_class -> source_file = class_def -> get_source_file().data();
            new_class -> access_flags = class_def -> get_access_flags();
            new_class -> direct_methods_size = class_data_item.get_number_of_direct_methods();
            new_class -> virtual_methods_size = class_data_item.get_number_of_virtual_methods();
            new_class -> instance_fields_size = class_data_item.get_number_of_instance_fields();
            new_class -> static_fields_size = class_data_item.get_number_of_static_fields();

            /// fill the methods
            new_class -> virtual_methods = (hdvmmethod_t * ) malloc(new_class -> virtual_methods_size * sizeof(hdvmmethod_t));
            for (size_t j = 0; j < new_class -> virtual_methods_size; j++) {
                fill_dex_method(class_data_item.get_virtual_method_by_id(j), &new_class->virtual_methods[j]);
                opaque_struct->methods.push_back(&new_class->virtual_methods[j]);
            }
            new_class -> direct_methods = (hdvmmethod_t * ) malloc(new_class -> direct_methods_size * sizeof(hdvmmethod_t));
            for (size_t j = 0; j < new_class -> direct_methods_size; j++) {
                fill_dex_method(class_data_item.get_direct_method_by_id(j), &new_class->direct_methods[j]);
                opaque_struct->methods.push_back(&new_class->direct_methods[j]);
            }
            /// fill the fields
            new_class -> instance_fields = (hdvmfield_t * ) malloc(new_class -> instance_fields_size * sizeof(hdvmfield_t));
            for (size_t j = 0; j < new_class -> instance_fields_size; j++)
                fill_dex_field(class_data_item.get_instance_field_by_id(j), & new_class -> instance_fields[j]);
            new_class -> static_fields = (hdvmfield_t * ) malloc(new_class -> static_fields_size * sizeof(hdvmfield_t));
            for (size_t j = 0; j < new_class -> static_fields_size; j++)
                fill_dex_field(class_data_item.get_static_field_by_id(j), & new_class -> static_fields[j]);
        }

    }

    void destroy_class_data(hdvmclass_t * class_) {
        if (class_ -> direct_methods) {
            free(class_ -> direct_methods);
            class_ -> direct_methods = nullptr;
        }
        if (class_ -> virtual_methods) {
            free(class_ -> virtual_methods);
            class_ -> virtual_methods = nullptr;
        }
        if (class_ -> static_fields) {
            free(class_ -> static_fields);
            class_ -> static_fields = nullptr;
        }
        if (class_ -> instance_fields) {
            free(class_ -> instance_fields);
            class_ -> instance_fields = nullptr;
        }
    }

    void destroy_opaque_struct(dex_opaque_struct_t * dex_opaque_struct) {
        if (dex_opaque_struct -> classes) {
            destroy_class_data(dex_opaque_struct -> classes);
            free(dex_opaque_struct -> classes);
            dex_opaque_struct -> classes = nullptr;
        }

        if (dex_opaque_struct -> parser) {
            delete dex_opaque_struct -> parser;
            dex_opaque_struct -> parser = nullptr;
        }
    }

}

hDexContext parse_dex(const char * filePath) {
    auto * opaque_struct = new dex_opaque_struct_t();
    shuriken::parser::dex::Parser * parser;

    try {
        parser = shuriken::parser::parse_dex(filePath);
    } catch (std::runtime_error & ) {
        return nullptr;
    }
    opaque_struct -> parser = parser;
    fill_dex_opaque_struct(parser, opaque_struct);

    return reinterpret_cast < hDexContext > (opaque_struct);
}

void destroy_dex(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return;
    destroy_opaque_struct(opaque_struct);
}

size_t get_number_of_strings(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return 0;
    auto * p = opaque_struct->parser;
    auto & strings = p -> get_strings();
    return strings.get_number_of_strings();
}

const char * get_string_by_id(hDexContext context, size_t i) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return nullptr;
    auto * p = opaque_struct->parser;
    auto & strings = p -> get_strings();
    if (i >= strings.get_number_of_strings()) return nullptr;
    return reinterpret_cast <
            const char * > (strings.get_string_by_id(i).data());
}

uint16_t get_number_of_classes(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return 0;
    return opaque_struct->number_of_classes;
}

hdvmclass_t * get_class_by_id(hDexContext context, uint16_t i) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG || i >= opaque_struct->number_of_classes) return 0;
    return &opaque_struct->classes[i];
}