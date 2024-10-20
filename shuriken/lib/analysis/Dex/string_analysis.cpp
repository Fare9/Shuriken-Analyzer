//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file string_analysis.cpp

#include "shuriken/analysis/Dex/dex_analysis.h"

using namespace shuriken::analysis::dex;

StringAnalysis::StringAnalysis(std::string_view value)
    : value(value) {
}

shuriken::iterator_range<class_method_idx_iterator_t> StringAnalysis::get_xreffrom() {
    return make_range(xreffrom.begin(), xreffrom.end());
}

void StringAnalysis::add_xreffrom(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset) {
    xreffrom.emplace_back(std::make_tuple(c, m, offset));
}

std::string_view StringAnalysis::get_value() {
    return value;
}