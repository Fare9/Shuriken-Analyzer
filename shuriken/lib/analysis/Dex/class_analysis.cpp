//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file class_analysis.cpp

#include "shuriken/analysis/Dex/dex_analysis.h"
#include "shuriken/common/iterator_range.h"
#include "shuriken/common/logger.h"
#include "shuriken/disassembler/Dex/internal_disassembler.h"

using namespace shuriken::analysis::dex;

std::string_view java_lang_object = "Ljava/lang/Object;";

ClassAnalysis::ClassAnalysis(shuriken::parser::dex::ClassDef *class_def) : class_def(class_def), is_external(false), name_("") {
}

ClassAnalysis::ClassAnalysis(ExternalClass *class_def) : class_def(class_def), is_external(true), name_("") {
}

void ClassAnalysis::add_method(MethodAnalysis *method_analysis) {
    auto method_key = method_analysis->get_full_name();

    methods.insert({method_key, method_analysis});

    if (is_external)
        std::get<ExternalClass *>(class_def)
                ->add_external_method(method_analysis->get_external_method());
}

size_t ClassAnalysis::get_nb_methods() const {
    return methods.size();
}

size_t ClassAnalysis::get_nb_fields() const {
    return fields.size();
}

shuriken::parser::dex::ClassDef *ClassAnalysis::get_classdef() {
    return std::get<shuriken::parser::dex::ClassDef *>(class_def);
}

ExternalClass *ClassAnalysis::get_externalclass() {
    return std::get<ExternalClass *>(class_def);
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

shuriken::iterator_range<ClassAnalysis::id_method_iterator_t> ClassAnalysis::get_methods() {
    return make_range(methods.begin(), methods.end());
}

MethodAnalysis *ClassAnalysis::get_method_analysis(
        std::variant<shuriken::parser::dex::EncodedMethod *, ExternalMethod *> method) {

    std::string_view method_name;

    if (std::holds_alternative<ExternalMethod *>(method))
        method_name = std::get<ExternalMethod *>(method)->pretty_method_name();
    else
        method_name = std::get<shuriken::parser::dex::EncodedMethod *>(method)->getMethodID()->dalvik_name_format();

    return methods[method_name];
}

shuriken::iterator_range<ClassAnalysis::id_field_iterator_t> ClassAnalysis::get_fields() {
    return make_range(fields.begin(), fields.end());
}

FieldAnalysis *ClassAnalysis::get_field_analysis(shuriken::parser::dex::EncodedField *field) {
    std::string_view name = field->get_field()->pretty_field();

    if (fields.find(name) == fields.end())
        return nullptr;

    return fields[name].get();
}

FieldAnalysis *ClassAnalysis::get_field_analysis(ExternalField *field) {
    std::string_view name = field->pretty_field_name();

    if (fields.find(name) == fields.end())
        return nullptr;

    return fields[name].get();
}

void ClassAnalysis::add_field_xref_read(MethodAnalysis *method,
                                        ClassAnalysis *classobj,
                                        std::variant<shuriken::parser::dex::EncodedField *,
                                                     ExternalField *>
                                                field,
                                        std::uint64_t off) {
    if (std::holds_alternative<shuriken::parser::dex::EncodedField *>(field)) {
        auto f = std::get<shuriken::parser::dex::EncodedField *>(field);
        std::string_view name = f->get_field()->pretty_field();
        if (fields.find(name) == fields.end())
            fields.insert({name, std::make_unique<FieldAnalysis>(f)});
        fields[name]->add_xrefread(classobj, method, off);
    } else {
        auto f = std::get<ExternalField *>(field);
        std::string_view name = f->pretty_field_name();
        if (fields.find(name) == fields.end())
            fields.insert({name, std::make_unique<FieldAnalysis>(f)});
        fields[name]->add_xrefread(classobj, method, off);
    }
}

void ClassAnalysis::add_field_xref_write(MethodAnalysis *method,
                                         ClassAnalysis *classobj,
                                         std::variant<shuriken::parser::dex::EncodedField *,
                                                      ExternalField *>
                                                 field,
                                         std::uint64_t off) {
    if (std::holds_alternative<shuriken::parser::dex::EncodedField *>(field)) {
        auto f = std::get<shuriken::parser::dex::EncodedField *>(field);
        std::string_view name = f->get_field()->pretty_field();
        if (fields.find(name) == fields.end())
            fields.insert({name, std::make_unique<FieldAnalysis>(f)});
        fields[name]->add_xrefwrite(classobj, method, off);
    } else {
        auto f = std::get<ExternalField *>(field);
        std::string_view name = f->pretty_field_name();
        if (fields.find(name) == fields.end())
            fields.insert({name, std::make_unique<FieldAnalysis>(f)});
        fields[name]->add_xrefwrite(classobj, method, off);
    }
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
    xrefnewinstance.emplace_back(methodobj, offset);
}

void ClassAnalysis::add_xref_const_class(MethodAnalysis *methodobj, std::uint64_t offset) {
    xrefconstclass.emplace_back(methodobj, offset);
}

shuriken::iterator_range<classxref_t::iterator> ClassAnalysis::get_xrefto() {
    return make_range(xrefto.begin(), xrefto.end());
}

shuriken::iterator_range<classxref_t::iterator> ClassAnalysis::get_xrefsfrom() {
    return make_range(xrefsfrom.begin(), xrefsfrom.end());
}

shuriken::iterator_range<std::vector<std::pair<MethodAnalysis *, std::uint64_t>>::iterator> ClassAnalysis::get_xrefnewinstance() {
    return make_range(xrefnewinstance.begin(), xrefnewinstance.end());
}

shuriken::iterator_range<std::vector<std::pair<MethodAnalysis *, std::uint64_t>>::iterator> ClassAnalysis::get_xrefconstclass() {
    return make_range(xrefconstclass.begin(), xrefconstclass.end());
}