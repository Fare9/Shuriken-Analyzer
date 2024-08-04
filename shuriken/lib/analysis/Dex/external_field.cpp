//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file external_field.cpp

#include "shuriken/analysis/Dex/external_field.h"

using namespace shuriken::analysis::dex;

ExternalField::ExternalField(std::string_view class_idx, std::string_view name_idx, std::string_view type) : class_idx(class_idx), name_idx(name_idx), type(type) {
}

std::string_view ExternalField::get_class_idx() const {
    return class_idx;
}

std::string_view ExternalField::get_name_idx() const {
    return name_idx;
}

std::string_view ExternalField::get_type_idx() const {
    return type;
}

std::string_view ExternalField::pretty_field_name() {
    if (!pretty_name.empty())
        return pretty_name;
    pretty_name = class_idx;
    pretty_name += "->";
    pretty_name += name_idx;
    pretty_name += " ";
    pretty_name += type;
    return pretty_name;
}

shuriken::dex::TYPES::access_flags ExternalField::get_access_flags() const {
    return access_flags;
}