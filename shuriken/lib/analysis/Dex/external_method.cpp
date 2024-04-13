//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file external_method.cpp

#include "shuriken/analysis/Dex/external_method.h"

using namespace shuriken::analysis::dex;

ExternalMethod::ExternalMethod(std::string_view class_idx, std::string_view name_idx, std::string_view proto_idx,
    shuriken::dex::TYPES::access_flags access_flags)
    : class_idx(class_idx), name_idx(name_idx), proto_idx(proto_idx), access_flags(access_flags) {
}

std::string_view ExternalMethod::get_class_idx() const {
    return class_idx;
}

std::string_view ExternalMethod::get_name_idx() const {
    return name_idx;
}

std::string_view ExternalMethod::get_proto_idx() const {
    return proto_idx;
}

std::string_view ExternalMethod::pretty_method_name() {
    if (!pretty_name.empty())
        return pretty_name;
    pretty_name = class_idx;
    pretty_name += "->";
    pretty_name += name_idx;
    pretty_name += proto_idx;
    return pretty_name;
}

shuriken::dex::TYPES::access_flags ExternalMethod::get_access_flags() const {
    return access_flags;
}