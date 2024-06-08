//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file methods.cpp

#include "shuriken/parser/Dex/dex_methods.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;
using method_ids_t = std::vector<std::unique_ptr<MethodID>>;
using it_methods = shuriken::iterator_range<method_ids_t::iterator>;
using it_const_methods = shuriken::iterator_range<const method_ids_t::iterator>;

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

std::string_view MethodID::get_method_name() {
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
    auto my_logger = shuriken::logger();
    auto current_offset = stream.tellg();
    std::uint16_t class_idx;
    std::uint16_t proto_idx;
    std::uint32_t name_idx;

    std::unique_ptr<MethodID> method_id;

    my_logger->info("Started parsing methods at offset {}", methods_offset);

    stream.seekg(methods_offset, std::ios_base::beg);

    for (size_t I = 0; I < methods_size; ++I) {
        stream.read_data<std::uint16_t>(class_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint16_t>(proto_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint32_t>(name_idx, sizeof(std::uint32_t));

        // create method id
        method_id = std::make_unique<MethodID>(
                types.get_type_by_id(class_idx),
                protos.get_proto_by_id(proto_idx),
                strings.get_string_by_id(name_idx));
        method_ids.push_back(std::move(method_id));
    }

    my_logger->info("Finshed parsing methods");

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

it_methods DexMethods::get_methods() {
    return make_range(method_ids.begin(), method_ids.end());
}

it_const_methods DexMethods::get_methods_const() {
    return make_range(method_ids.begin(), method_ids.end());
}

size_t DexMethods::get_number_of_methods() const {
    return method_ids.size();
}

MethodID *DexMethods::get_method_by_id(std::uint32_t id) {
    if (id >= method_ids.size())
        throw std::runtime_error("Error method id out of bound");
    return method_ids.at(id).get();
}