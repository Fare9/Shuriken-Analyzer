//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file mapitem.h
// @brief The map contains all the different data from the DEX file contained in
// the data section. Androguard retrieves all the information from here, but
// in some cases, contains fewer data than the header.

#ifndef SHURIKENLIB_DEX_MAPITEM_H
#define SHURIKENLIB_DEX_MAPITEM_H

#include "shuriken/common/iterator_range.h"
#include "shuriken/common/shurikenstream.h"
#include <unordered_map>

namespace shuriken::parser::dex {
    class DexMapList {
    public:
        /// @brief all possible type codes from the
        /// mapitems
        enum type_codes : std::uint16_t {
            TYPE_HEADER_ITEM = 0x0000,
            TYPE_STRING_ID_ITEM = 0x0001,
            TYPE_TYPE_ID_ITEM = 0x0002,
            TYPE_PROTO_ID_ITEM = 0x0003,
            TYPE_FIELD_ID_ITEM = 0x0004,
            TYPE_METHOD_ID_ITEM = 0x0005,
            TYPE_CLASS_DEF_ITEM = 0x0006,
            TYPE_CALL_SITE_ID_ITEM = 0x0007,
            TYPE_METHOD_HANDLE_ITEM = 0x0008,
            TYPE_MAP_LIST = 0x1000,
            TYPE_TYPE_LIST = 0x1001,
            TYPE_ANNOTATION_SET_REF_LIST = 0x1002,
            TYPE_ANNOTATION_SET_ITEM = 0x1003,
            TYPE_CLASS_DATA_ITEM = 0x2000,
            TYPE_CODE_ITEM = 0x2001,
            TYPE_STRING_DATA_ITEM = 0x2002,
            TYPE_DEBUG_INFO_ITEM = 0x2003,
            TYPE_ANNOTATION_ITEM = 0x2004,
            TYPE_ENCODED_ARRAY_ITEM = 0x2005,
            TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006,
            TYPE_HIDDENAPI_CLASS_DATA_ITEM = 0xF000
        };

        /// @brief Map to store each item type name with its value
        const std::unordered_map<std::uint16_t, std::string> type_names = {
                {TYPE_HEADER_ITEM, "TYPE_HEADER_ITEM"},
                {TYPE_STRING_ID_ITEM, "TYPE_STRING_ID_ITEM"},
                {TYPE_TYPE_ID_ITEM, "TYPE_TYPE_ID_ITEM"},
                {TYPE_PROTO_ID_ITEM, "TYPE_PROTO_ID_ITEM"},
                {TYPE_FIELD_ID_ITEM, "TYPE_FIELD_ID_ITEM"},
                {TYPE_METHOD_ID_ITEM, "TYPE_METHOD_ID_ITEM"},
                {TYPE_CLASS_DEF_ITEM, "TYPE_CLASS_DEF_ITEM"},
                {TYPE_CALL_SITE_ID_ITEM, "TYPE_CALL_SITE_ID_ITEM"},
                {TYPE_METHOD_HANDLE_ITEM, "TYPE_METHOD_HANDLE_ITEM"},
                {TYPE_MAP_LIST, "TYPE_MAP_LIST"},
                {TYPE_TYPE_LIST, "TYPE_TYPE_LIST"},
                {TYPE_ANNOTATION_SET_REF_LIST, "TYPE_ANNOTATION_SET_REF_LIST"},
                {TYPE_ANNOTATION_SET_ITEM, "TYPE_ANNOTATION_SET_ITEM"},
                {TYPE_CLASS_DATA_ITEM, "TYPE_CLASS_DATA_ITEM"},
                {TYPE_CODE_ITEM, "TYPE_CODE_ITEM"},
                {TYPE_STRING_DATA_ITEM, "TYPE_STRING_DATA_ITEM"},
                {TYPE_DEBUG_INFO_ITEM, "TYPE_DEBUG_INFO_ITEM"},
                {TYPE_ANNOTATION_ITEM, "TYPE_ANNOTATION_ITEM"},
                {TYPE_ENCODED_ARRAY_ITEM, "TYPE_ENCODED_ARRAY_ITEM"},
                {TYPE_ANNOTATIONS_DIRECTORY_ITEM, "TYPE_ANNOTATIONS_DIRECTORY_ITEM"},
                {TYPE_HIDDENAPI_CLASS_DATA_ITEM, "TYPE_HIDDENAPI_CLASS_DATA_ITEM"}};

        /// @brief Map that store the information of the map
        struct map_item {
            type_codes type;     //! type of the item
            std::uint16_t unused;//! not used, do not retrieve it
            std::uint32_t size;  //! number of items to be found on the offset
            std::uint32_t offset;//! offset where to read the items
        };

    public:
        /// @brief items specified by the type
        using map_data_item_t = std::unordered_map<type_codes, map_item>;
        /// @brief iterator to the map
        using it_map_data = iterator_range<map_data_item_t::iterator>;
        /// @brief constant iterator to the map
        using it_const_map_data = iterator_range<const map_data_item_t::iterator>;

    private:
        /// @brief Map of items, each type code will contain a map item
        map_data_item_t items;

    public:
        /// @brief Constructor of the DexMapList
        DexMapList() = default;
        /// @brief Destructor of the DexMapList
        ~DexMapList() = default;

        /// @brief Parse the map list from the DEX file to create the map
        /// @param stream DEX file content
        /// @param map_off offset to the map_list
        void parse_map_list(common::ShurikenStream &stream, std::uint32_t map_off);

        /// @return iterator to the map with the items
        it_map_data get_map_items();

        /// @return constant iterator the the map with the items
        it_const_map_data get_map_items_const();
    };

}// namespace shuriken::parser::dex

#endif//SHURIKENLIB_DEX_MAPITEM_H
