//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file mapitem.cpp

#include "shuriken/parser/Dex/dex_mapitem.h"
#include "shuriken/common/logger.h"
#include <string>

using namespace shuriken::parser::dex;


void DexMapList::parse_map_list(common::ShurikenStream &stream, std::uint32_t map_off) {
    auto current_offset = stream.tellg();

    std::uint32_t size;

    map_item item;

    log(LEVEL::INFO, "Started parsing map_list at offset {}", std::to_string(map_off));

    stream.seekg(map_off, std::ios_base::beg);

    // first read the size
    stream.read_data<std::uint32_t>(size, sizeof(std::uint32_t));

    for (size_t I = 0; I < size; ++I) {
        stream.read_data<map_item>(item, sizeof(map_item));

        items[item.type] = {item.type, item.unused, item.size, item.offset};
    }

    log(LEVEL::INFO, "Finished parsing map_list");
    stream.seekg(current_offset, std::ios_base::beg);
}

DexMapList::it_map_data DexMapList::get_map_items() {
    return make_range(items.begin(), items.end());
}

DexMapList::it_const_map_data DexMapList::get_map_items_const() {
    return make_range(items.begin(), items.end());
}