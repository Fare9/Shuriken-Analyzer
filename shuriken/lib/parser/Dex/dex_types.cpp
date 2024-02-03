//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file DexTypes.cpp

#include "shuriken/parser/Dex/dex_types.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

// --DexTypes

std::unique_ptr<DVMType> DexTypes::parse_type(std::string_view name) {
    switch (name.at(0)) {

        case 'Z':
            return std::make_unique<DVMFundamental>(fundamental_e::BOOLEAN, name);
        case 'B':
            return std::make_unique<DVMFundamental>(fundamental_e::BYTE, name);
        case 'C':
            return std::make_unique<DVMFundamental>(fundamental_e::CHAR, name);
        case 'D':
            return std::make_unique<DVMFundamental>(fundamental_e::DOUBLE, name);
        case 'F':
            return std::make_unique<DVMFundamental>(fundamental_e::FLOAT, name);
        case 'I':
            return std::make_unique<DVMFundamental>(fundamental_e::INT, name);
        case 'J':
            return std::make_unique<DVMFundamental>(fundamental_e::LONG, name);
        case 'S':
            return std::make_unique<DVMFundamental>(fundamental_e::SHORT, name);
        case 'V':
            return std::make_unique<DVMFundamental>(fundamental_e::VOID, name);
        case 'L':
            return std::make_unique<DVMClass>(name);
        case '[':
        {
            size_t depth = 0;
            for (const auto &c : name) {
                if (c == '[') depth++;
                else break;
            }
            std::string_view aux(name.begin()+depth, name.end());
            std::unique_ptr<DVMType> aux_type = parse_type(aux);
            return std::make_unique<DVMArray>(depth, aux_type, name);
        }
        default:
            return std::make_unique<Unknown>(name);
    }
}

void DexTypes::parse_types(common::ShurikenStream& shurikenStream,
                           DexStrings& strings_,
                           std::uint32_t offset_types,
                           std::uint32_t n_of_types) {
    auto my_logger = shuriken::logger();
    my_logger->info("Start parsing types");

    auto current_offset = shurikenStream.tellg();

    std::unique_ptr<DVMType> type;
    std::uint32_t type_id;

    shurikenStream.seekg(offset_types, std::ios_base::beg);

    for (size_t I = 0; I < n_of_types; ++I) {
        shurikenStream.read_data<std::uint32_t>(type_id, sizeof(std::uint32_t));

        type = parse_type(strings_.get_string_by_id(type_id));

        ordered_types.push_back(std::move(type));
    }

    shurikenStream.seekg(current_offset, std::ios_base::beg);
    my_logger->info("Finished parsing types");
}

void DexTypes::to_xml(std::ofstream &fos) {
    fos << "<DexTypes>\n";

    for (size_t I = 0; I < ordered_types.size(); ++I)
    {
        fos << "\t<type>\n";
        fos << "\t\t<id>" << I << "</id>\n";
        fos << "\t\t<value>" << ordered_types[I]->print_type() << "</value>\n";
        fos << "\t</type>\n";
    }

    fos << "</DexTypes>\n";
}

const DVMType* DexTypes::get_type_by_id_const(std::uint32_t id) const {
    if (id >= ordered_types.size()) {
        throw std::runtime_error("Error id for type provided is incorrect");
    }

    return ordered_types.at(id).get();
}


DVMType* DexTypes::get_type_by_id(std::uint32_t id) {
    if (id >= ordered_types.size()) {
        throw std::runtime_error("Error id for type provided is incorrect");
    }

    return ordered_types.at(id).get();
}

std::int64_t DexTypes::get_id_by_type(DVMType * type) {
    auto it = std::ranges::find_if(ordered_types,
                                    [&](const std::unique_ptr<DVMType>& t) {
        return *type == *t;
    });

    if (it == ordered_types.end())
        return -1;

    return std::distance(ordered_types.begin(), it);
}

// --DVMType
DVMType::DVMType(type_e type, std::string_view raw_type)
        : type(type), raw_type(raw_type)
{}

type_e DVMType::get_type() const {
    return type;
}

std::string_view DVMType::get_raw_type() const {
    return raw_type;
}


// --DVMFundamental
DVMFundamental::DVMFundamental(fundamental_e fundamental, std::string_view raw_name)
    : DVMType(type_e::FUNDAMENTAL, raw_name), fundamental(fundamental) {
    if (!fundamental_s.contains(fundamental)) {
        throw std::runtime_error("Error fundamental value provided doesn't exist");
    }
    name = std::string_view(fundamental_s.at(fundamental));
}

std::string DVMFundamental::print_type() {
    return std::string(name);
}

std::string_view DVMFundamental::get_name() const {
    return name;
}

fundamental_e DVMFundamental::get_fundamental_type() const {
    return fundamental;
}

// --DVMClass

DVMClass::DVMClass(std::string_view raw_name) :
        DVMType(type_e::CLASS, raw_name) {
    if (raw_name.empty() || raw_name.length() == 1)
        std::runtime_error("Incorrect length for DVMClass");
    if (!raw_name.starts_with('L') || !raw_name.ends_with(';'))
        std::runtime_error("Incorrect class name");

    class_name = raw_name.substr(1, raw_name.length()-2);
    std::replace(class_name.begin(), class_name.end(), '/', '.');

    class_name_v = std::string_view (class_name);
}

std::string DVMClass::print_type() {
    return class_name;
}

std::string_view DVMClass::get_class_name() const {
    return class_name_v;
}

// --DVMArray

DVMArray::DVMArray(size_t depth,
            std::unique_ptr<DVMType>& array_type,
            std::string_view raw_name) :
        DVMType(type_e::ARRAY, raw_name),
        depth(depth), array_type(std::move(array_type)) {
    array_name = this->array_type->print_type();
    for (size_t I = 0; I < depth; ++I) array_name += "[]";
    array_name_v = std::string_view(array_name);
}

std::string DVMArray::print_type() {
    return array_name;
}

std::string_view DVMArray::get_array_string() const {
    return array_name_v;
}

size_t DVMArray::get_array_depth() const {
    return depth;
}

const DVMType* DVMArray::get_array_base_type() const {
    return array_type.get();
}

// --Unknown

Unknown::Unknown(std::string_view raw) :
        DVMType(type_e::UNKNOWN, raw)
{

}

std::string Unknown::print_type()
{
    return "Unknown";
}
