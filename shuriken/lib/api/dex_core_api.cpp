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
    hdvmtype_t* new_type(const shuriken::parser::dex::DVMType* type) {
        auto t = type->get_type();

        if (t == shuriken::parser::dex::FUNDAMENTAL) {
            auto* fund = reinterpret_cast<const shuriken::parser::dex::DVMFundamental*>(type);
            return new hdvmtype_t{
                    .type = FUNDAMENTAL,
                    .raw_type = reinterpret_cast<const char*>(type->get_raw_type().data()),
                    .fundamental = hdvmfundamental_t{
                            .fundamental = static_cast<hfundamental_e>(fund->get_fundamental_type()),
                            .name = reinterpret_cast<const char*>(fund->get_name().data())
                    }
            };
        } else if (t == shuriken::parser::dex::CLASS) {
            auto* cls = reinterpret_cast<const shuriken::parser::dex::DVMClass*>(type);
            return new hdvmtype_t{
                    .type = CLASS,
                    .raw_type = reinterpret_cast<const char*>(type->get_raw_type().data()),
                    .class_type = hdvmclass_t{
                            .class_name = reinterpret_cast<const char*>(cls->get_class_name().data())
                    }
            };
        } else if (t == shuriken::parser::dex::ARRAY) {
            auto* array = reinterpret_cast<const shuriken::parser::dex::DVMArray*>(type);
            return new hdvmtype_t{
                    .type = ARRAY,
                    .raw_type = reinterpret_cast<const char*>(type->get_raw_type().data()),
                    .array_type = hdvmarray_t{
                            .array_name = reinterpret_cast<const char*>(array->get_array_string().data()),
                            .depth = array->get_array_depth(),
                            .array_type = new_type(array->get_array_base_type())
                    }
            };
        }
        return nullptr;
    }

    void delete_type(hdvmtype_t* type) {
        if (type == nullptr) return;
        delete type;
        type = nullptr;
    }

}


hDexParser parse_dex(const char* filePath) {
    shuriken::parser::dex::Parser* parser;

    try {
        parser = shuriken::parser::parse_dex(filePath);
    } catch (std::runtime_error&) {
        return nullptr;
    }

    return reinterpret_cast<hDexParser>(parser);
}

void destroy_dex(hDexParser parser) {
    if (!parser) return;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    delete p;
}

h_dex_header_t * get_dex_header(hDexParser parser) {
    if (!parser) return nullptr;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    auto& header = p->get_header();
    return reinterpret_cast<h_dex_header_t*>(&header.get_dex_header());
}

size_t get_number_of_strings(hDexParser parser) {
    if (!parser) return 0;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    auto& strings = p->get_strings();
    return strings.get_number_of_strings();
}

const char* get_string_by_id(hDexParser parser, size_t i) {
    if (!parser) return nullptr;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    auto& strings = p->get_strings();
    if (i >= strings.get_number_of_strings()) return nullptr;
    return reinterpret_cast<const char*>(strings.get_string_by_id(i).data());
}

size_t get_number_of_types(hDexParser parser) {
    if (!parser) return 0;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    return p->get_types().get_number_of_types();
}

size_t get_number_of_methods(hDexParser parser) {
    if (!parser) return 0;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    return p->get_methods().get_number_of_methods();
}

size_t get_number_of_classes(hDexParser parser) {
    if (!parser) return 0;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    return p->get_header().get_dex_header().class_defs_size;
}


hdvmmethod_t* get_methods_list(hDexParser parser) {
    if (!parser) return 0;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    auto it = p->get_methods().get_methods();
    auto size = std::distance(it.begin(), it.end());
    hdvmmethod_t *method_vec = (hdvmmethod_t*)malloc(size * sizeof(hdvmmethod_t));
    auto cur = 0;
    for (const auto& method : it) {
        method_vec[cur].belonging_class = method->get_class()->get_raw_type().data();
        method_vec[cur].name = method->get_method_name().data();
        method_vec[cur].pretty_name = method->pretty_method().c_str();
        method_vec[cur].protoId = method->get_prototype()->get_shorty_idx().data();
        ++cur;
    }
    assert(cur == size -1);
    return method_vec;
}

hdvmtype_t* get_type_by_id(hDexParser parser, size_t i) {
    if (!parser) return nullptr;
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    auto&types = p->get_types();
    return new_type(types.get_type_by_id_const(i));
}


hdex_class_t* get_classes(hDexParser parser) {
    if (!parser) return nullptr;
    auto size = get_number_of_classes(parser);
    auto* p = reinterpret_cast<shuriken::parser::dex::Parser*>(parser);
    auto it = p->get_classes().get_classdefs();
    hdex_class_t *class_vec = (hdex_class_t*)malloc(size * sizeof(hdvmclass_t));
    auto cur = 0;
    for (const auto& c : it) {
        const auto class_def = c.get();
        const auto class_idx = class_def->get_class_idx();
        const auto super_class = class_def->get_superclass();
        auto access_flags = class_def->get_access_flags();
        auto& class_data_item = class_def->get_class_data_item();
        auto& class_def_struct = class_def->get_class_def_struct();

        class_vec[cur].class_name = class_idx->get_class_name().data();// Assign with new char[] or std::string.c_str() if using std::string
        class_vec[cur].super_class = super_class->get_class_name().data();
        class_vec[cur].source_file = class_def->get_source_file().data();
        class_vec[cur].access_flags = static_cast<std::uint32_t>(access_flags);
        class_vec[cur].interfaces_off = class_def_struct.interfaces_off;
        class_vec[cur].annotations_off = class_def_struct.annotations_off;
        class_vec[cur].class_data_off = class_def_struct.class_data_off;
        class_vec[cur].static_values_off = class_def_struct.static_values_off;
        class_vec[cur].static_fields_size = class_data_item.get_number_of_static_fields() ;
        class_vec[cur].instance_fields_size = class_data_item.get_number_of_instance_fields();
        class_vec[cur].direct_methods_size = class_data_item.get_number_of_direct_methods();
        class_vec[cur].virtual_methods_size = class_data_item.get_number_of_virtual_methods();
        // Increment cur or ensure it's correctly indexed for each iteration
        //TODO:parse direct methods
        cur++;
    }
    assert(cur == size -1);
    return class_vec;

}

void destroy_type(hdvmtype_t *dvmtype) {
    delete_type(dvmtype);
}




