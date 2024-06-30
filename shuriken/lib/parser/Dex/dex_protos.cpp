//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file protos.cpp

#include "shuriken/parser/Dex/dex_protos.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;


// -- ProtoID
using parameters_type_t = std::vector<DVMType *>;
using it_params = shuriken::iterator_range<parameters_type_t::iterator>;
using it_const_params = shuriken::iterator_range<const parameters_type_t::iterator>;

void ProtoID::parse_parameters(
        common::ShurikenStream &stream,
        DexTypes &types,
        std::uint32_t parameters_off) {
    auto my_logger = shuriken::logger();
    auto current_offset = stream.tellg();
    std::uint32_t n_parameters;
    std::uint16_t type_id;

    if (!parameters_off)
        return;

    my_logger->debug("Started parsing parameter at offset {}", parameters_off);

    stream.seekg(parameters_off, std::ios_base::beg);

    // read the number of parameters
    stream.read_data<std::uint32_t>(n_parameters, sizeof(std::uint32_t));

    for (std::uint32_t I = 0; I < n_parameters; ++I) {
        stream.read_data<std::uint16_t>(type_id, sizeof(std::uint16_t));
        parameters.push_back(types.get_type_by_id(type_id));
    }

    my_logger->debug("Finished parsing parameter at offset{}", parameters_off);

    stream.seekg(current_offset, std::ios_base::beg);
}

ProtoID::ProtoID(
        shuriken::common::ShurikenStream &stream,
        DexTypes &types,
        std::string_view shorty_idx,
        std::uint32_t return_type_idx,
        std::uint32_t parameters_off)
    : shorty_idx(shorty_idx), return_type(types.get_type_by_id(return_type_idx)) {
    parse_parameters(stream, types, parameters_off);
}

std::string_view ProtoID::get_shorty_idx() const {
    return shorty_idx;
}

const DVMType *ProtoID::get_return_type() const {
    return return_type;
}

DVMType *ProtoID::get_return_type() {
    return return_type;
}

std::string_view ProtoID::get_dalvik_prototype() {
    if (prototypes_dalvik_representation.empty()) {
        prototypes_dalvik_representation = "(";
        for (auto parameter: parameters) {
            prototypes_dalvik_representation += parameter->get_raw_type();
        }
        prototypes_dalvik_representation += ")";
        prototypes_dalvik_representation += return_type->get_raw_type();
    }
    return prototypes_dalvik_representation;
}

it_params ProtoID::get_parameters() {
    return make_range(parameters.begin(), parameters.end());
}

it_const_params ProtoID::get_parameters_const() {
    return make_range(parameters.begin(), parameters.end());
}


// -- DexProtos
void DexProtos::parse_protos(common::ShurikenStream &stream,
                             std::uint32_t number_of_protos,
                             std::uint32_t offset,
                             DexStrings &strings,
                             DexTypes &types) {
    auto my_logger = shuriken::logger();
    auto current_offset = stream.tellg();

    std::unique_ptr<ProtoID> proto = nullptr;
    std::uint32_t shorty_idx = 0,//! id for prototype string
            return_type_idx = 0, //! id for type of return
            parameters_off = 0;  //! offset of parameters

    my_logger->info("Started parsing of protos");

    stream.seekg(offset, std::ios_base::beg);

    for (size_t I = 0; I < number_of_protos; ++I) {
        stream.read_data<std::uint32_t>(shorty_idx, sizeof(std::uint32_t));
        stream.read_data<std::uint32_t>(return_type_idx, sizeof(std::uint32_t));
        stream.read_data<std::uint32_t>(parameters_off, sizeof(std::uint32_t));

        proto = std::make_unique<ProtoID>(stream, types, strings.get_string_by_id(shorty_idx),
                                          return_type_idx, parameters_off);
        protos.push_back(std::move(proto));
    }

    my_logger->info("Finished parsing of protos");

    stream.seekg(current_offset, std::ios_base::beg);
}

void DexProtos::to_xml(std::ofstream &xml_file) {
    xml_file << "<protos>\n";

    for (const auto &protoid: protos) {
        xml_file << "\t<proto>\n";

        xml_file << "\t\t<parameters>\n";
        for (auto param: protoid->get_parameters()) {
            xml_file << "\t\t\t<parameter>\n";
            xml_file << "\t\t\t\t<type>" << param->print_type() << "</type>\n";
            xml_file << "\t\t\t\t<raw>" << param->print_type() << "</raw>\n";
            xml_file << "\t\t\t</parameter>\n";
        }
        xml_file << "\t\t</parameters>\n";

        xml_file << "\t\t<return>\n";
        xml_file << "\t\t\t\t<type>" << protoid->get_return_type()->print_type() << "</type>\n";
        xml_file << "\t\t\t\t<raw>" << protoid->get_return_type()->print_type() << "</raw>\n";
        xml_file << "\t\t</return>\n";

        xml_file << "\t</proto>\n";
    }

    xml_file << "</protos>\n";
}

DexProtos::protos_id_s_t &DexProtos::get_all_protos() {
    if (protos_cache_s.empty() || protos.size() != protos_cache_s.size()) {
        protos_cache_s.clear();
        for (const auto &entry: protos)
            protos_cache_s.push_back(std::ref(*entry));
    }

    return protos_cache_s;
}

DexProtos::it_protos DexProtos::get_protos() {
    auto &aux = get_all_protos();
    return deref_iterator_range(aux);
}

DexProtos::it_const_protos DexProtos::get_protos_const() {
    const auto &aux = get_all_protos();
    return deref_iterator_range(aux);
}

ProtoID *DexProtos::get_proto_by_id(std::uint32_t id) {
    if (id >= protos.size())
        throw std::runtime_error("Error proto id given is out of bound");
    return protos[id].get();
}

std::int64_t DexProtos::get_id_by_proto(ProtoID *proto) {
    auto it = std::ranges::find_if(protos,
                                   [&](const std::unique_ptr<ProtoID> &p) {
                                       return *proto == *p;
                                   });

    if (it == protos.end())
        return -1;

    return std::distance(protos.begin(), it);
}

size_t DexProtos::get_number_of_protos() const {
    return protos.size();
}