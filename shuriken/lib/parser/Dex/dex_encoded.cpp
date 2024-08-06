//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
// @author Ernesto Java <javaernesto@gmail.com>
//
// @file encoded.cpp

#include "shuriken/parser/Dex/dex_encoded.h"
#include "shuriken/common/logger.h"
#include <sstream>

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

size_t EncodedArray::get_encodedarray_size() const {
    return values.size();
}

EncodedArray::it_encoded_value EncodedArray::get_encoded_values() {
    auto &aux = get_encoded_values_vector();
    return deref_iterator_range(aux);
}

EncodedArray::it_const_encoded_value EncodedArray::get_encoded_values_const() {
    const auto &aux = get_encoded_values_vector();
    return deref_iterator_range(aux);
}

EncodedArray::encoded_values_s_t &EncodedArray::get_encoded_values_vector() {
    if (values_s.empty() || values_s.size() != values.size()) {
        values_s.clear();
        for (const auto &entry: values)
            values_s.push_back(std::ref(*entry));
    }
    return values_s;
}

// AnnotationElement
AnnotationElement::AnnotationElement(std::string_view name,
                                     std::unique_ptr<EncodedValue> value) : name(name), value(std::move(value)) {
}

std::string_view AnnotationElement::get_name() const {
    return name;
}

EncodedValue *AnnotationElement::get_value() {
    return value.get();
}


void EncodedAnnotation::parse_encoded_annotation(common::ShurikenStream &stream,
                                                 DexTypes &types,
                                                 DexStrings &strings) {
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
        annotation = std::make_unique<AnnotationElement>(strings.get_string_by_id(static_cast<uint32_t>(name_idx)), std::move(value));
        // add the anotation to the vector
        annotations.push_back(std::move(annotation));
    }
}

DVMType *EncodedAnnotation::get_annotation_type() {
    return type;
}

size_t EncodedAnnotation::get_number_of_annotations() const {
    return annotations.size();
}

EncodedAnnotation::it_annotation_elements EncodedAnnotation::get_annotations() {
    auto &aux = get_annotations_vector();
    return deref_iterator_range(aux);
}

EncodedAnnotation::it_const_annotation_elements EncodedAnnotation::get_annotations_const() {
    const auto &aux = get_annotations_vector();
    return deref_iterator_range(aux);
}

EncodedAnnotation::annotation_elements_s_t &EncodedAnnotation::get_annotations_vector() {
    if (annotations_s.empty() || annotations_s.size() != annotations.size()) {
        annotations_s.clear();
        for (const auto &entry: annotations)
            annotations_s.push_back(std::ref(*entry));
    }
    return annotations_s;
}

AnnotationElement *EncodedAnnotation::get_annotation_by_pos(std::uint32_t pos) {
    if (pos >= annotations.size())
        throw std::runtime_error("Error pos annotation out of bound");
    return annotations[pos].get();
}

void EncodedValue::parse_encoded_value(common::ShurikenStream &stream,
                                       DexTypes &types,
                                       DexStrings &strings) {
    /*auto my_logger = shuriken::logger();*/

    auto transform_u32_to_bytevector = [&](std::uint32_t intValue) {
        auto &value_data = std::get<std::vector<std::uint8_t>>(value);
        for (size_t i = 0; i < sizeof(uint32_t); ++i) {
            value_data.push_back(static_cast<uint8_t>((intValue >> (i * 8)) & 0xFF));
        }
    };

    auto transform_i32_to_bytevector = [&](std::int32_t intValue) {
        auto &value_data = std::get<std::vector<std::uint8_t>>(value);
        for (size_t i = 0; i < sizeof(int32_t); ++i) {
            value_data.push_back(static_cast<uint8_t>((intValue >> (i * 8)) & 0xFF));
        }
    };

    auto transform_u64_to_bytevector = [&](std::uint64_t intValue) {
        auto &value_data = std::get<std::vector<std::uint8_t>>(value);
        for (size_t i = 0; i < sizeof(std::uint64_t); ++i) {
            value_data.push_back(static_cast<uint8_t>((intValue >> (i * 8)) & 0xFF));
        }
    };

    auto transform_i64_to_bytevector = [&](std::int64_t intValue) {
        auto &value_data = std::get<std::vector<std::uint8_t>>(value);
        for (size_t i = 0; i < sizeof(std::int64_t); ++i) {
            value_data.push_back(static_cast<uint8_t>((intValue >> (i * 8)) & 0xFF));
        }
    };

    // read the value format
    std::uint8_t aux;
    stream.read_data<std::uint8_t>(aux, sizeof(std::uint8_t));
    format = static_cast<shuriken::dex::TYPES::value_format>(aux & 0x1f);
    auto arg = (aux >> 5);

    switch (format) {
        case shuriken::dex::TYPES::value_format::VALUE_BYTE: {
            auto value = stream.readSignedInt(arg) & 0xFF;
            transform_i32_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_SHORT: {
            auto value = stream.readSignedInt(arg) & 0xFFFF;
            transform_i32_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_CHAR: {
            auto value = stream.readUnsignedInt(arg, false) & 0xFFFF;
            transform_u32_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_INT: {
            auto value = stream.readSignedInt(arg);
            transform_i32_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_FLOAT: {
            auto value = stream.readUnsignedInt(arg, true);
            transform_u32_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_LONG: {
            auto value = stream.readSignedLong(arg);
            transform_i64_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_DOUBLE: {
            auto value = stream.readUnsignedLong(arg, true);
            transform_u64_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_STRING:
        case shuriken::dex::TYPES::value_format::VALUE_TYPE:
        case shuriken::dex::TYPES::value_format::VALUE_FIELD:
        case shuriken::dex::TYPES::value_format::VALUE_METHOD:
        case shuriken::dex::TYPES::value_format::VALUE_ENUM: {
            auto value = stream.readUnsignedInt(arg, false);
            transform_u32_to_bytevector(value);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_BOOLEAN: {
            auto &value_data = std::get<std::vector<std::uint8_t>>(value);
            value_data.push_back(arg);
            break;
        }
        case shuriken::dex::TYPES::value_format::VALUE_NULL:
            break;
        case shuriken::dex::TYPES::value_format::VALUE_ARRAY: {
            auto &array = std::get<std::unique_ptr<EncodedArray>>(value);
            array = std::make_unique<EncodedArray>();
            array->parse_encoded_array(stream, types, strings);
        }
        case shuriken::dex::TYPES::value_format::VALUE_ANNOTATION: {
            auto &annotation = std::get<std::unique_ptr<EncodedAnnotation>>(value);
            annotation = std::make_unique<EncodedAnnotation>();
            annotation->parse_encoded_annotation(stream, types, strings);
        }
        default:
            std::stringstream error_msg;
            error_msg << "Value for format not implemented: " << static_cast<std::uint32_t>(format);
            error_msg << "(arg: " << arg << ")";
            throw std::runtime_error(error_msg.str());
    }
}

shuriken::dex::TYPES::value_format EncodedValue::get_value_format() const {
    return format;
}

EncodedValue::it_data_buffer EncodedValue::get_data_buffer() {
    if (format == shuriken::dex::TYPES::value_format::VALUE_ARRAY ||
        format == shuriken::dex::TYPES::value_format::VALUE_ANNOTATION)
        throw std::runtime_error("Error value does not contain a data buffer");
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    return make_range(value_data.begin(), value_data.end());
}

EncodedArray *EncodedValue::get_array_data() {
    if (format == shuriken::dex::TYPES::value_format::VALUE_ARRAY)
        return std::get<std::unique_ptr<EncodedArray>>(value).get();
    return nullptr;
}

EncodedAnnotation *EncodedValue::get_annotation_data() {
    if (format == shuriken::dex::TYPES::value_format::VALUE_ANNOTATION)
        return std::get<std::unique_ptr<EncodedAnnotation>>(value).get();
    return nullptr;
}

std::int32_t EncodedValue::convert_data_to_int() {
    if (format != shuriken::dex::TYPES::value_format::VALUE_INT)
        throw std::runtime_error("Error encoded value is not an int type");
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    return *(reinterpret_cast<std::int32_t *>(value_data.data()));
}

std::int64_t EncodedValue::convert_data_to_long() {
    if (format != shuriken::dex::TYPES::value_format::VALUE_LONG)
        throw std::runtime_error("Error encoded value is not a long type");
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    return *(reinterpret_cast<std::int64_t *>(value_data.data()));
}

std::uint8_t EncodedValue::convert_data_to_byte() {
    if (format != shuriken::dex::TYPES::value_format::VALUE_BYTE)
        throw std::runtime_error("Error encoded value is not a byte type");
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    return *(reinterpret_cast<std::uint8_t *>(value_data.data()));
}

std::int16_t EncodedValue::convert_data_to_short() {
    if (format != shuriken::dex::TYPES::value_format::VALUE_SHORT)
        throw std::runtime_error("Error encoded value is not a short type");
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    return *(reinterpret_cast<std::int16_t *>(value_data.data()));
}

double EncodedValue::convert_data_to_double() {
    union long_double {
        std::uint64_t long_bits;
        double double_bits;
    };
    if (format != shuriken::dex::TYPES::value_format::VALUE_DOUBLE)
        throw std::runtime_error("Error encoded value is not a double type");
    long_double data;
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    data.long_bits = *(reinterpret_cast<std::uint64_t *>(value_data.data()));
    return data.double_bits;
}

float EncodedValue::convert_data_to_float() {
    union int_float {
        std::uint32_t int_bits;
        float float_bits;
    };
    if (format != shuriken::dex::TYPES::value_format::VALUE_FLOAT)
        throw std::runtime_error("Error encoded value is not a float type");
    int_float data;
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    data.int_bits = *(reinterpret_cast<std::uint32_t *>(value_data.data()));
    return data.float_bits;
}

std::uint16_t EncodedValue::convert_data_to_char() {
    if (format != shuriken::dex::TYPES::value_format::VALUE_CHAR)
        throw std::runtime_error("Error encoded value is not a char type");
    auto &value_data = std::get<std::vector<std::uint8_t>>(value);
    return *(reinterpret_cast<std::uint16_t *>(value_data.data()));
}

EncodedField::EncodedField(FieldID *field_idx, shuriken::dex::TYPES::access_flags flags)
    : field_idx(field_idx), flags(flags) {
    this->field_idx->set_encoded_field(this);
}

const FieldID *EncodedField::get_field() const {
    return field_idx;
}

FieldID *EncodedField::get_field() {
    return field_idx;
}

shuriken::dex::TYPES::access_flags EncodedField::get_flags() {
    return flags;
}

void EncodedField::set_initial_value(EncodedArray *initial_value) {
    this->initial_value = initial_value;
}

const EncodedArray *EncodedField::get_initial_value() const {
    return initial_value;
}

EncodedArray *EncodedField::get_initial_value() {
    return initial_value;
}

void EncodedCatchHandler::parse_encoded_catch_handler(common::ShurikenStream &stream,
                                                      DexTypes &types) {
    std::uint64_t type_idx, addr;

    /// the offset of the EncodedCatchHandler
    offset = static_cast<std::uint64_t>(stream.tellg());
    /// Size of the handlers
    size = stream.read_sleb128();

    for (size_t I = 0, S = std::abs(size); I < S; ++I) {
        type_idx = stream.read_uleb128();
        addr = stream.read_uleb128();

        handlers.push_back({.type = types.get_type_by_id(static_cast<uint32_t>(type_idx)),
                            .idx = addr});
    }

    // A size of 0 means that there is a catch-all but no explicitly typed catches
    // And a size of -1 means that there is one typed catch along with a catch-all.
    if (size <= 0) {
        catch_all_addr = stream.read_uleb128();
    }
}

bool EncodedCatchHandler::has_explicit_typed_catches() const {
    if (size >= 0) return true;// user should check size of handlers
    return false;
}

std::int64_t EncodedCatchHandler::get_size() const {
    return size;
}

std::uint64_t EncodedCatchHandler::get_catch_all_addr() const {
    return catch_all_addr;
}

std::uint64_t EncodedCatchHandler::get_offset() const {
    return offset;
}

EncodedCatchHandler::it_handler_pairs EncodedCatchHandler::get_handle_pairs() {
    return make_range(handlers.begin(), handlers.end());
}

void CodeItemStruct::parse_code_item_struct(common::ShurikenStream &stream,
                                            DexTypes &types) {
    // instructions are read in chunks of 16 bits
    std::uint8_t instruction[2];
    size_t I;
    std::unique_ptr<EncodedCatchHandler> encoded_catch_handler;

    /// first read the code_item_struct_t
    stream.read_data<code_item_struct_t>(code_item, sizeof(code_item_struct_t));

    // now we can work with the values

    // first read the instructions for the CodeItem
    instructions_raw.reserve(code_item.insns_size * 2);

    for (I = 0; I < code_item.insns_size; ++I) {
        // read the instruction
        stream.read_data<std::uint8_t[2]>(instruction, sizeof(std::uint8_t[2]));
        instructions_raw.push_back(instruction[0]);
        instructions_raw.push_back(instruction[1]);
    }

    if ((code_item.tries_size > 0) &&// padding present in case tries_size > 0
        (code_item.insns_size % 2)) {// and instructions size is odd

        // padding advance 2 bytes
        stream.seekg(sizeof(std::uint16_t), std::ios_base::cur);
    }

    // check if there are try-catch stuff
    if (code_item.tries_size > 0) {

        TryItem try_item = {0, 0, 0};

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

std::uint16_t CodeItemStruct::get_registers_size() const {
    return code_item.registers_size;
}

std::uint16_t CodeItemStruct::get_incomings_args() const {
    return code_item.ins_size;
}

std::uint16_t CodeItemStruct::get_outgoing_args() const {
    return code_item.outs_size;
}

std::uint16_t CodeItemStruct::get_number_try_items() const {
    return code_item.tries_size;
}

std::uint16_t CodeItemStruct::get_offset_to_debug_info() const {
    return code_item.debug_info_off;
}

std::uint16_t CodeItemStruct::get_instructions_size() const {
    return code_item.insns_size;
}

std::span<std::uint8_t> CodeItemStruct::get_bytecode() {
    std::span bytecode{instructions_raw};
    return bytecode;
}

CodeItemStruct::it_try_items CodeItemStruct::get_try_items() {
    return make_range(try_items.begin(), try_items.end());
}

std::uint64_t CodeItemStruct::get_encoded_catch_handler_offset() {
    return encoded_catch_handler_list_offset;
}

CodeItemStruct::it_encoded_catch_handlers CodeItemStruct::get_encoded_catch_handlers() {
    auto &aux = get_encoded_catch_handlers_vector();
    return deref_iterator_range(aux);
}

CodeItemStruct::encoded_catch_handlers_s_t &CodeItemStruct::get_encoded_catch_handlers_vector() {
    if (encoded_catch_handlers_s.empty() || encoded_catch_handlers.size() != encoded_catch_handlers_s.size()) {
        encoded_catch_handlers_s.clear();
        for (const auto &entry: encoded_catch_handlers)
            encoded_catch_handlers_s.push_back(std::ref(*entry));
    }
    return encoded_catch_handlers_s;
}

EncodedMethod::EncodedMethod(MethodID *method_id, shuriken::dex::TYPES::access_flags access_flags)
    : method_id(method_id), access_flags(access_flags) {}

void EncodedMethod::parse_encoded_method(common::ShurikenStream &stream,
                                         std::uint64_t code_off,
                                         DexTypes &types) {
    auto current_offset = stream.tellg();

    if (code_off > 0) {
        stream.seekg(code_off, std::ios_base::beg);
        // parse the code item
        code_item = std::make_unique<CodeItemStruct>();
        code_item->parse_code_item_struct(stream, types);
    }

    // return to current offset
    stream.seekg(current_offset, std::ios_base::beg);
}

const MethodID *EncodedMethod::getMethodID() const {
    return method_id;
}

MethodID *EncodedMethod::getMethodID() {
    return method_id;
}

shuriken::dex::TYPES::access_flags EncodedMethod::get_flags() {
    return access_flags;
}

const CodeItemStruct *EncodedMethod::get_code_item() const {
    return code_item.get();
}

CodeItemStruct *EncodedMethod::get_code_item() {
    return code_item.get();
}
