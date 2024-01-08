//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
// @author Ernesto Java <javaernesto@gmail.com>
//
// @file encoded.cpp

#include "shuriken/parser/Dex/dex_encoded.h"

using namespace shuriken::parser::dex;

void EncodedArray::parse_encoded_array(common::ShurikenStream &stream,
                                       shuriken::parser::dex::DexTypes &types,
                                       shuriken::parser::dex::DexStrings &strings) {
    auto array_size = stream.read_uleb128();
    std::unique_ptr<EncodedValue> value = nullptr;

    for (std::uint64_t I = 0; I < array_size; ++I) {
        value = std::make_unique<EncodedValue>();
        value->parse_encoded_value(stream, types, strings);
        values.push_back(std::move(value));
    }
}

void EncodedAnnotation::parse_encoded_annotation(common::ShurikenStream & stream,
                                                 DexTypes & types,
                                                 DexStrings & strings) {
    std::unique_ptr<AnnotationElement> annotation;
    std::unique_ptr<EncodedValue> value;
    std::uint64_t name_idx;
    auto type_idx = stream.read_uleb128();
    auto size = stream.read_uleb128();

    type = types.get_type_by_id(static_cast<std::uint32_t>(type_idx));

    for (std::uint64_t I = 0; I < size; ++I) {
        // read first the name_idx
        name_idx = stream.read_uleb128();
        // then the EncodedValue
        value = std::make_unique<EncodedValue>();
        value->parse_encoded_value(stream, types, strings);
        // now create an annotation element
        annotation = std::make_unique<AnnotationElement>(strings.get_string_by_id(name_idx), std::move(value));
        // add the anotation to the vector
        annotations.push_back(std::move(annotation));
    }

}

void EncodedValue::parse_encoded_value(common::ShurikenStream & stream,
                                       DexTypes & types,
                                       DexStrings & strings) {
    auto read_from_stream = [&](size_t size) {
        std::uint8_t aux;
        auto& value_data = std::get<std::vector<std::uint8_t>>(value);
        for(size_t I = 0; I <= size; ++I) {
            stream.read_data<std::uint8_t>(aux, sizeof(std::uint8_t));
            value_data.push_back(aux);
        }
    };

    // read the value format
    std::uint8_t aux;
    stream.read_data<std::uint8_t>(aux, sizeof(std::uint8_t));
    format = static_cast<shuriken::dex::TYPES::value_format>(aux & 0x1f);
    auto size = (aux >> 5);

    switch (format) {
        case shuriken::dex::TYPES::value_format::VALUE_BYTE:
        case shuriken::dex::TYPES::value_format::VALUE_SHORT:
        case shuriken::dex::TYPES::value_format::VALUE_CHAR:
        case shuriken::dex::TYPES::value_format::VALUE_INT:
        case shuriken::dex::TYPES::value_format::VALUE_FLOAT:
        case shuriken::dex::TYPES::value_format::VALUE_LONG:
        case shuriken::dex::TYPES::value_format::VALUE_DOUBLE:
        case shuriken::dex::TYPES::value_format::VALUE_STRING:
        case shuriken::dex::TYPES::value_format::VALUE_TYPE:
        case shuriken::dex::TYPES::value_format::VALUE_FIELD:
        case shuriken::dex::TYPES::value_format::VALUE_METHOD:
        case shuriken::dex::TYPES::value_format::VALUE_ENUM:
        {
            read_from_stream(size);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_ARRAY:
        {
            auto& array = std::get<std::unique_ptr < EncodedArray >>(value);
            array = std::make_unique<EncodedArray>();
            array->parse_encoded_array(stream, types, strings);
        }
        case shuriken::dex::TYPES::value_format::VALUE_ANNOTATION:
        {
            auto& annotation = std::get<std::unique_ptr < EncodedAnnotation >>(value);
            annotation = std::make_unique<EncodedAnnotation>();
            annotation->parse_encoded_annotation(stream, types, strings);
        }
        default:
            throw std::runtime_error("Value for format not implemented");
    }
}

void EncodedCatchHandler::parse_encoded_catch_handler(common::ShurikenStream& stream,
                                                      DexTypes& types) {
    std::uint64_t type_idx, addr;

    /// the offset of the EncodedCatchHandler
    offset = static_cast<std::uint64_t>(stream.tellg());
    /// Size of the handlers
    size = stream.read_sleb128();

    for (size_t I = 0, S = std::abs(size); I < S; ++I) {
        type_idx = stream.read_uleb128();
        addr = stream.read_uleb128();

        handlers.push_back({
            .type = types.get_type_by_id(type_idx),
            .idx = addr
        });
    }

    // A size of 0 means that there is a catch-all but no explicitly typed catches
    // And a size of -1 means that there is one typed catch along with a catch-all.
    if (size <= 0) {
        catch_all_addr = stream.read_uleb128();
    }
}

void CodeItemStruct::parse_code_item_struct(common::ShurikenStream& stream,
                                            DexTypes& types) {
    // instructions are read in chunks of 16 bits
    std::uint8_t instruction[2];
    size_t I;
    std::unique_ptr<EncodedCatchHandler> encoded_catch_handler;

    /// first read the code_item_struct_t
    stream.read_data<code_item_struct_t>(code_item, sizeof(code_item_struct_t));

    // now we can work with the values

    // first read the instructions for the CodeItem
    instructions_raw.reserve(code_item.insns_size*2);

    for (I = 0; I < code_item.insns_size; ++I) {
        // read the instruction
        stream.read_data<std::uint8_t[2]>(instruction, sizeof(std::uint8_t[2]));
        instructions_raw.push_back(instruction[0]);
        instructions_raw.push_back(instruction[1]);
    }

    if ((code_item.tries_size > 0) && // padding present in case tries_size > 0
        (code_item.insns_size % 2)) {   // and instructions size is odd

        // padding advance 2 bytes
        stream.seekg(sizeof(std::uint16_t), std::ios_base::cur);
    }

    // check if there are try-catch stuff
    if (code_item.tries_size > 0) {

        TryItem try_item = {0};

        for (I = 0; I < code_item.tries_size; ++I) {
            stream.read_data<TryItem>(try_item, sizeof(TryItem));
            try_items.push_back(try_item);
        }

        encoded_catch_handler_list_offset =
                static_cast<std::uint64_t>(stream.tellg());

        // now get the number of catch handlers
        encoded_catch_handler_size = stream.read_uleb128();

        for (I = 0; I < encoded_catch_handler_size; ++I) {
            encoded_catch_handler = std::make_unique<EncodedCatchHandler>();
            encoded_catch_handler->parse_encoded_catch_handler(stream, types);
            encoded_catch_handlers.push_back(std::move(encoded_catch_handler));
        }
    }
}

void EncodedMethod::parse_encoded_method(common::ShurikenStream& stream,
                                         std::uint64_t code_off,
                                         DexTypes& types) {
    auto current_offset = stream.tellg();

    if (code_off > 0)
    {
        stream.seekg(code_off, std::ios_base::beg);
        // parse the code item
        code_item = std::make_unique<CodeItemStruct>();
        code_item->parse_code_item_struct(stream, types);
    }

    // return to current offset
    stream.seekg(current_offset, std::ios_base::beg);
}