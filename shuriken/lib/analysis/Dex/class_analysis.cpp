//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file class_analysis.cpp

#include "shuriken/analysis/Dex/dex_analysis.h"
#include "shuriken/disassembler/Dex/internal_disassembler.h"
#include "shuriken/common/logger.h"

using namespace shuriken::analysis::dex;

std::string_view java_lang_object = "Ljava/lang/Object;";

ClassAnalysis::ClassAnalysis(shuriken::parser::dex::ClassDef * class_def) :
    class_def(class_def), is_external(false) {
}

ClassAnalysis::ClassAnalysis(ExternalClass * class_def) :
    class_def(class_def), is_external(true) {
}

void ClassAnalysis::add_method(MethodAnalysis *method_analysis) {
    auto method_key = method_analysis->get_full_name();

    methods[method_key] = method_analysis;

    if (is_external)
        std::get<ExternalClass*>(class_def)
                ->add_external_method(method_analysis->get_external_method());
}

size_t ClassAnalysis::get_nb_methods() const {
    return methods.size();
}

size_t ClassAnalysis::get_nb_fields() const {
    return fields.size();
}

shuriken::parser::dex::ClassDef * ClassAnalysis::get_classdef() {
    return std::get<shuriken::parser::dex::ClassDef *>(class_def);
}

ExternalClass * ClassAnalysis::get_externalclass() {
    return std::get<ExternalClass*>(class_def);
}

bool ClassAnalysis::is_class_external() const {
    return is_external;
}

std::string_view ClassAnalysis::extends() {
    if (!extends_.empty()) return extends_;

    if (is_external)
        extends_ = java_lang_object;
    else
        extends_ = get_classdef()->get_superclass()->get_raw_type();
    return extends_;
}

std::string_view ClassAnalysis::name() {
    if (!name_.empty())
        return name_;

    if (is_external)
        name_ = get_externalclass()->get_name();
    else
        name_ = get_classdef()->get_class_idx()->get_raw_type();

    return name_;
}

shuriken::parser::dex::ClassDef::it_interfaces_list ClassAnalysis::implements() {
    if (is_external) throw std::runtime_error("implements: external class is not supported for implemented interfaces");
    return get_classdef()->get_interfaces();
}

MethodAnalysis *ClassAnalysis::get_method_analysis(
        std::variant<shuriken::parser::dex::EncodedMethod *, ExternalMethod *> method) {

    std::string_view method_name;

    if (std::holds_alternative<ExternalMethod*>(method))
        method_name = std::get<ExternalMethod*>(method)->pretty_method_name();
    else
        method_name = std::get<shuriken::parser::dex::EncodedMethod *>(method)->getMethodID()->dalvik_name_format();

    return methods[method_name];
}

FieldAnalysis *ClassAnalysis::get_field_analysis(shuriken::parser::dex::EncodedField *field) {
    std::string_view name = field->get_field()->pretty_field();

    if (fields.find(name) == fields.end())
        return nullptr;

    return fields[name].get();
}

void ClassAnalysis::add_field_xref_read(MethodAnalysis *method,
                         ClassAnalysis *classobj,
                         shuriken::parser::dex::EncodedField *field,
                         std::uint64_t off) {
    std::string_view name = field->get_field()->pretty_field();
    if (fields.find(name) == fields.end())
        fields[name] = std::make_unique<FieldAnalysis>(field);
    fields[name]->add_xrefread(classobj, method, off);
}

void ClassAnalysis::add_field_xref_write(MethodAnalysis *method,
                          ClassAnalysis *classobj,
                          shuriken::parser::dex::EncodedField *field,
                          std::uint64_t off) {
    std::string_view name = field->get_field()->pretty_field();
    if (fields.find(name) == fields.end())
        fields[name] = std::make_unique<FieldAnalysis>(field);
    fields[name]->add_xrefwrite(classobj, method, off);
}

void ClassAnalysis::add_method_xref_to(MethodAnalysis *method1,
                        ClassAnalysis *classobj,
                        MethodAnalysis *method2,
                        std::uint64_t off) {
    auto method_key = method1->get_full_name();

    if (methods.find(method_key) == methods.end())
        add_method(method1);
    methods[method_key]->add_xrefto(classobj, method2, off);
}

void ClassAnalysis::add_method_xref_from(MethodAnalysis *method1,
                          ClassAnalysis *classobj,
                          MethodAnalysis *method2,
                          std::uint64_t off) {
    auto method_key = method1->get_full_name();

    if (methods.find(method_key) == methods.end())
        add_method(method1);
    methods[method_key]->add_xreffrom(classobj, method2, off);
}

void ClassAnalysis::add_xref_to(shuriken::dex::TYPES::ref_type ref_kind,
                 ClassAnalysis *classobj,
                 MethodAnalysis *methodobj,
                 std::uint64_t offset) {
    xrefto[classobj].insert(std::make_tuple(ref_kind, methodobj, offset));
}

void ClassAnalysis::add_xref_from(shuriken::dex::TYPES::ref_type ref_kind,
                   ClassAnalysis *classobj,
                   MethodAnalysis *methodobj,
                   std::uint64_t offset) {
    xrefsfrom[classobj].insert(std::make_tuple(ref_kind, methodobj, offset));
}

void ClassAnalysis::add_xref_new_instance(MethodAnalysis *methodobj, std::uint64_t offset) {
    xrefnewinstance.push_back(std::make_pair(methodobj, offset));
}

void ClassAnalysis::add_xref_const_class(MethodAnalysis *methodobj, std::uint64_t offset) {
    xrefconstclass.push_back(std::make_pair(methodobj, offset));
}
