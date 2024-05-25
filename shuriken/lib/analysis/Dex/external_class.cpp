//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file external_class.cpp

#include "shuriken/analysis/Dex/external_class.h"

using namespace shuriken::analysis::dex;

ExternalClass::ExternalClass(std::string_view name)
    : name(name) {
}

std::string_view ExternalClass::get_name() {
    return name;
}

shuriken::iterator_range<std::vector<ExternalMethod*>::iterator> ExternalClass::get_methods() {
    return make_range(methods.begin(), methods.end());
}

shuriken::iterator_range<
std::vector<std::unique_ptr<shuriken::parser::dex::EncodedField>>::iterator>
ExternalClass::get_fields() {
    return make_range(fields.begin(), fields.end());
}

void ExternalClass::add_external_method(ExternalMethod* method) {
    methods.emplace_back(method);
}

void ExternalClass::add_external_field(shuriken::parser::dex::FieldID* field) {
    fields.emplace_back(std::make_unique<shuriken::parser::dex::EncodedField>(field, shuriken::dex::TYPES::access_flags::NONE));
}

