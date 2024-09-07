//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file methods.cpp

#include "shuriken/parser/Dex/dex_methods.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

const DVMType *MethodID::get_class() const {
    return class_;
}

DVMType *MethodID::get_class() {
    return class_;
}

const ProtoID *MethodID::get_prototype() const {
    return protoId;
}

ProtoID *MethodID::get_prototype() {
    return protoId;
}

std::string_view MethodID::get_method_name() const {
    return name;
}

std::string_view MethodID::demangle() {
    if (!demangled_name.empty())
        return demangled_name;

    demangled_name = protoId->get_return_type()->print_type();
    demangled_name += " " + class_->print_type() + "->";
    demangled_name += std::string(name) + "(";

    for (const auto &p: protoId->get_parameters_const()) {
        demangled_name += p->print_type() + ",";
    }

    if (demangled_name.ends_with(','))
        demangled_name.pop_back();

    demangled_name += ")";
    return demangled_name;
}

std::string_view MethodID::dalvik_name_format() {
    if (!dalvik_name.empty())
        return dalvik_name;
    dalvik_name = class_->get_raw_type();
    dalvik_name += "->" + std::string(name) + "(";
    for (const auto proto: protoId->get_parameters())
        dalvik_name += proto->get_raw_type();
    dalvik_name += ")" + std::string(protoId->get_return_type()->get_raw_type());
    return dalvik_name;
}

void DexMethods::parse_methods(
        common::ShurikenStream &stream,
        DexTypes &types,
        DexProtos &protos,
        DexStrings &strings,
        std::uint32_t methods_offset,
        std::uint32_t methods_size) {
    auto current_offset = stream.tellg();
    std::uint16_t class_idx;
    std::uint16_t proto_idx;
    std::uint32_t name_idx;

    std::unique_ptr<MethodID> method_id;

    log(LEVEL::INFO, "Started parsing methods at offset {}", std::to_string(methods_offset));

    stream.seekg(methods_offset, std::ios_base::beg);

    for (uint32_t I = 0; I < methods_size; ++I) {
        stream.read_data<std::uint16_t>(class_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint16_t>(proto_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint32_t>(name_idx, sizeof(std::uint32_t));

        // create method id
        method_id = std::make_unique<MethodID>(
                types.get_type_by_id(class_idx),
                protos.get_proto_by_id(proto_idx),
                strings.get_string_by_id(name_idx),
                I,
                class_idx
                );
        method_ids.push_back(std::move(method_id));
    }

    log(LEVEL::INFO, "Finshed parsing methods");

    stream.seekg(current_offset, std::ios_base::beg);
}

void DexMethods::to_xml(std::ofstream &fos) {
    fos << "<DexMethods>\n";
    for (const auto &m: method_ids) {
        fos << "\t<method>\n";
        fos << "\t\t<type>" << m->get_prototype()->get_shorty_idx() << "</type>\n";
        fos << "\t\t<name>" << m->get_method_name() << "</name>\n";
        fos << "\t\t<class>" << m->get_class()->print_type() << "</type>\n";
        fos << "\t</method>\n";
    }
    fos << "</DexMethods>\n";
}

DexMethods::it_methods DexMethods::get_methods() {
    auto &aux = get_methods_vector();
    return deref_iterator_range(aux);
}

DexMethods::it_const_methods DexMethods::get_methods_const() {
    const auto &aux = get_methods_vector();
    return deref_iterator_range(aux);
}

DexMethods::method_ids_s_t &DexMethods::get_methods_vector() {
    if (method_ids_s.empty() || method_ids.size() != method_ids_s.size()) {
        method_ids_s.clear();
        for (const auto &entry: method_ids)
            method_ids_s.push_back(std::ref(*entry));
    }
    return method_ids_s;
}

size_t DexMethods::get_number_of_methods() const {
    return method_ids.size();
}

MethodID *DexMethods::get_method_by_id(std::uint32_t id) {
    if (id >= method_ids.size())
        throw std::runtime_error("Error method id out of bound");
    return method_ids.at(id).get();
}