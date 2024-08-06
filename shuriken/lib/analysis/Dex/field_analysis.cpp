//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file field_analysis.cpp

#include "shuriken/analysis/Dex/dex_analysis.h"

using namespace shuriken::analysis::dex;

FieldAnalysis::FieldAnalysis(parser::dex::EncodedField *field)
    : field(field), external(false), name(field->get_field()->pretty_field()) {
}

FieldAnalysis::FieldAnalysis(ExternalField *field)
    : field(field), external(true), name(field->pretty_field_name()) {
}

bool FieldAnalysis::is_external() const {
    return external;
}

shuriken::parser::dex::EncodedField *FieldAnalysis::get_encoded_field() const {
    return std::get<shuriken::parser::dex::EncodedField *>(field);
}

ExternalField *FieldAnalysis::get_external_field() const {
    return std::get<ExternalField *>(field);
}

std::string_view FieldAnalysis::get_name() {
    return name;
}

shuriken::iterator_range<class_method_idx_iterator_t> FieldAnalysis::get_xrefread() {
    return make_range(xrefread.begin(), xrefread.end());
}

shuriken::iterator_range<class_method_idx_iterator_t> FieldAnalysis::get_xrefwrite() {
    return make_range(xrefwrite.begin(), xrefwrite.end());
}

void FieldAnalysis::add_xrefread(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset) {
    xrefread.emplace_back(std::make_tuple(c, m, offset));
}

void FieldAnalysis::add_xrefwrite(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset) {
    xrefwrite.emplace_back(std::make_tuple(c, m, offset));
}
