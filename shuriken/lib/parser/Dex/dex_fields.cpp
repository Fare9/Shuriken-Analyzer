//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file fields.cpp

#include "shuriken/parser/Dex/dex_fields.h"
#include "shuriken/common/logger.h"


using namespace shuriken::parser::dex;

FieldID::FieldID(DVMType *class_, DVMType *type_, std::string_view name_) : class_(class_), type_(type_), name_(name_) {}

const DVMType *FieldID::field_class() const {
    return class_;
}

DVMType *FieldID::field_class() {
    return class_;
}

const DVMType *FieldID::field_type() const {
    return type_;
}

DVMType *FieldID::field_type() {
    return type_;
}

std::string_view FieldID::field_name() const {
    return name_;
}

std::string_view FieldID::pretty_field() {
    if (!pretty_name.empty())
        return pretty_name;
    pretty_name = class_->print_type() + "->" +
                  std::string(name_) + " " +
                  type_->print_type();
    return pretty_name;
}

void FieldID::set_encoded_field(EncodedField *field) {
    this->encoded_field = field;
}

EncodedField *FieldID::get_encoded_field() {
    return this->encoded_field;
}

void DexFields::parse_fields(
        common::ShurikenStream &stream,
        DexTypes &types,
        DexStrings &strings,
        std::uint32_t fields_offset,
        std::uint32_t n_of_fields) {
    auto current_offset = stream.tellg();
    auto my_logger = shuriken::logger();
    std::uint16_t class_idx, type_idx;
    std::uint32_t name_idx;
    std::unique_ptr<FieldID> field_id = nullptr;

    my_logger->info("Started parsing of fields at offset {}", fields_offset);

    stream.seekg(fields_offset, std::ios_base::beg);

    for (size_t I = 0; I < n_of_fields; ++I) {
        stream.read_data<std::uint16_t>(class_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint16_t>(type_idx, sizeof(std::uint16_t));
        stream.read_data<std::uint32_t>(name_idx, sizeof(std::uint32_t));

        field_id = std::make_unique<FieldID>(
                types.get_type_by_id(class_idx),
                types.get_type_by_id(type_idx),
                strings.get_string_by_id(name_idx));
        fields.push_back(std::move(field_id));
    }

    my_logger->info("Finished parsing of fields");
    stream.seekg(current_offset, std::ios_base::beg);
}

DexFields::it_field_ids DexFields::get_fields() {
    return make_range(fields.begin(), fields.end());
}

DexFields::it_const_field_ids DexFields::get_fields_const() {
    return make_range(fields.begin(), fields.end());
}

FieldID *DexFields::get_field_by_id(std::uint32_t id) {
    if (id >= fields.size())
        throw std::runtime_error("Error field id is out of bound");
    return fields[id].get();
}

std::int64_t DexFields::get_id_by_field(FieldID *field) {
    auto it = std::ranges::find_if(fields, [&](std::unique_ptr<FieldID> &f) {
        return *field == *f;
    });

    if (it == fields.end())
        return -1;

    return std::distance(fields.begin(), it);
}

void DexFields::to_xml(std::ofstream &fos) {
    fos << "<fields>\n";
    for (const auto &field: fields) {
        fos << "\t<field>\n";
        fos << "\t\t<type>" << field->field_type()->print_type() << "</type>\n";
        fos << "\t\t<name>" << field->field_name() << "</name>\n";
        fos << "\t\t<class>" << field->field_class()->print_type() << "</class>\n";
        fos << "\t</field>\n";
    }
    fos << "</fields>\n";
}