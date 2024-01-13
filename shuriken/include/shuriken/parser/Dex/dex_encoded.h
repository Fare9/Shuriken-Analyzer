//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file encoded.h
// @brief This file contains all the information from encoded data
// these classes are for annotations, arrays, fields, try-catch
// information, etc.

#ifndef SHURIKENLIB_DEX_ENCODED_H
#define SHURIKENLIB_DEX_ENCODED_H

#include "shuriken/common/shurikenstream.h"
#include "shuriken/common/iterator_range.h"
#include "shuriken/parser/Dex/dex_strings.h"
#include "shuriken/parser/Dex/dex_fields.h"
#include "shuriken/parser/Dex/dex_methods.h"
#include "shuriken/parser/Dex/dvm_types.h"

#include <iostream>
#include <vector>
#include <memory>
#include <variant>
#include <span>

namespace shuriken {
    namespace parser {
        namespace dex {
            // Forward declaration needed
            class EncodedValue;

            /// @brief Information of an array with encoded values
            class EncodedArray {
            public: using encoded_values_t = std::vector < std::unique_ptr < EncodedValue >> ;
                using it_encoded_value = iterator_range < encoded_values_t::iterator > ;
                using it_const_encoded_value = iterator_range <
                        const encoded_values_t::iterator > ;
            private:
                /// @brief encoded values of the array
                encoded_values_t values;
            public:
                /// @brief Constructor of the encoded array
                EncodedArray() =
                default;
                /// @brief Destructor of encoded array
                ~EncodedArray() =
                default;

                /// @brief Parse the encoded Array
                /// @param stream stream where to read data
                /// @param types object with types for parsing encoded array
                /// @param strings object with strings for parsing encoded array
                void parse_encoded_array(common::ShurikenStream & stream,
                                         DexTypes & types,
                                         DexStrings & strings);

                size_t get_encodedarray_size() const {
                    return values.size();
                }

                it_encoded_value get_encoded_values() {
                    return make_range(values.begin(), values.end());
                }

                it_const_encoded_value get_encoded_values_const() {
                    return make_range(values.begin(), values.end());
                }
            };

            /// @brief Annotation element with value and a name
            /// this is contained in the EncodedAnnotation class
            class AnnotationElement {
            private:
                /// @brief name of the annotation element
                std::string_view name;
                /// @brief Value of the annotation
                std::unique_ptr < EncodedValue > value;
            public:
                /// @brief Constructor of the annotation element
                /// @param name name of the annotation
                /// @param value value of the annotation
                AnnotationElement(std::string_view name,
                                  std::unique_ptr < EncodedValue > value):
                                  name(name), value(std::move(value))
                                  {}

                ~AnnotationElement() {}

                std::string_view get_name() const {
                    return name;
                }

                EncodedValue * get_value() {
                    return value.get();
                }
            };

            /// @brief Class to parse and create a vector of
            /// Annotations
            class EncodedAnnotation {
            public: using annotation_elements_t = std::vector < std::unique_ptr < AnnotationElement >> ;
                using it_annotation_elements = iterator_range < annotation_elements_t::iterator > ;
                using it_const_annotation_elements = iterator_range <
                        const annotation_elements_t::iterator > ;
            private:
                /// @brief Type of the annotation
                DVMType * type;
                /// @brief Array of annotation elements
                annotation_elements_t annotations;
            public:
                /// @brief Constructor of EncodedAnnotation, default one
                EncodedAnnotation() =
                default;
                /// @brief Destructor of EncodedAnnotation, default one
                ~EncodedAnnotation() =
                default;

                /// @brief Function to parse an encoded annotation
                /// @param stream stream with the DEX file
                /// @param types types for parsing the encoded annotation
                /// @param strings strings for parsing the encoded annotation
                void parse_encoded_annotation(common::ShurikenStream & stream,
                                              DexTypes & types,
                                              DexStrings & strings);

                /// @brief Get the type of the annotations
                /// @return annotations type
                DVMType * get_annotation_type() {
                    return type;
                }

                /// @brief Get the number of annotations
                /// @return number of annotations
                size_t get_number_of_annotations() const {
                    return annotations.size();
                }

                it_annotation_elements get_annotations() {
                    return make_range(annotations.begin(), annotations.end());
                }

                it_const_annotation_elements get_annotations_const() {
                    return make_range(annotations.begin(), annotations.end());
                }

                /// @brief Get an annotation element by position
                /// @param pos position to retrieve
                /// @return pointer to AnnotationElement
                AnnotationElement * get_annotation_by_pos(std::uint32_t pos) {
                    if (pos >= annotations.size())
                        throw std::runtime_error("Error pos annotation out of bound");
                    return annotations[pos].get();
                }
            };

            /// @brief encoded piece of (nearly) arbitrary hierarchically structured data.
            class EncodedValue {
                using data_buffer_t = std::vector < std::uint8_t > ;
                using it_data_buffer = iterator_range < data_buffer_t::iterator > ;
            private:
                /// @brief Format of the encoded value
                shuriken::dex::TYPES::value_format format;
                /// @brief have a vector of uint8_t for normal types
                /// @brief an encoded array in case the type is an array
                /// @brief an encoded annotation in case the type is an annotation
                std::variant < data_buffer_t,
                        std::unique_ptr < EncodedArray > ,
                        std::unique_ptr < EncodedAnnotation >> value;
            public:
                /// @brief Constructor of encoded value, default constructor
                EncodedValue() =
                default;
                /// @brief Destructor of encoded value
                ~EncodedValue() =
                default;

                void parse_encoded_value(common::ShurikenStream & stream,
                                         DexTypes & types,
                                         DexStrings & strings);

                shuriken::dex::TYPES::value_format get_value_format() const {
                    return format;
                }

                it_data_buffer get_data_buffer() {
                    if (format == shuriken::dex::TYPES::value_format::VALUE_ARRAY ||
                        format == shuriken::dex::TYPES::value_format::VALUE_ANNOTATION)
                        throw std::runtime_error("Error value does not contain a data buffer");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return make_range(value_data.begin(), value_data.end());
                }

                EncodedArray * get_array_data() {
                    if (format == shuriken::dex::TYPES::value_format::VALUE_ARRAY)
                        return std::get < std::unique_ptr < EncodedArray >> (value).get();
                    return nullptr;
                }

                EncodedAnnotation * get_annotation_data() {
                    if (format == shuriken::dex::TYPES::value_format::VALUE_ANNOTATION)
                        return std::get < std::unique_ptr < EncodedAnnotation >> (value).get();
                    return nullptr;
                }

                std::int32_t convert_data_to_int() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_INT)
                        throw std::runtime_error("Error encoded value is not an int type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < std::int32_t * > (value_data.data()));
                }

                std::int64_t convert_data_to_long() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_LONG)
                        throw std::runtime_error("Error encoded value is not a long type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < std::int64_t * > (value_data.data()));
                }

                std::uint8_t convert_data_to_byte() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_BYTE)
                        throw std::runtime_error("Error encoded value is not a byte type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < std::uint8_t * > (value_data.data()));
                }

                std::int16_t convert_data_to_short() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_SHORT)
                        throw std::runtime_error("Error encoded value is not a short type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < std::int16_t * > (value_data.data()));
                }

                double convert_data_to_double() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_DOUBLE)
                        throw std::runtime_error("Error encoded value is not a double type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < double * > (value_data.data()));
                }

                float convert_data_to_float() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_FLOAT)
                        throw std::runtime_error("Error encoded value is not a float type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < float * > (value_data.data()));
                }

                std::uint16_t convert_data_to_char() {
                    if (format != shuriken::dex::TYPES::value_format::VALUE_CHAR)
                        throw std::runtime_error("Error encoded value is not a char type");
                    auto & value_data = std::get < std::vector < std::uint8_t >> (value);
                    return * (reinterpret_cast < std::uint16_t * > (value_data.data()));
                }
            };

            /// @brief encoded field with information about the initial values
            class EncodedField {
            private:
                /// @brief FieldID of the EncodedField
                FieldID * field_idx;
                /// @brief access flags for the field
                shuriken::dex::TYPES::access_flags flags;
                /// @brief Initial Value
                EncodedArray* initial_value;
            public:
                /// @brief Constructor of an encoded field
                /// @param field_idx FieldID for the encoded field
                /// @param flags
                EncodedField(FieldID * field_idx, shuriken::dex::TYPES::access_flags flags)
                        : field_idx(field_idx), flags(flags) {}
                /// @brief Destructor of Encoded Field
                ~EncodedField() = default;

                /// @brief Get a constant pointer to the FieldID
                /// @return constant pointer to the FieldID
                const FieldID* get_field() const {
                    return field_idx;
                }

                /// @brief Get a pointer to the FieldID
                /// @return pointer to the FieldID
                FieldID* get_field() {
                    return field_idx;
                }

                /// @brief Get the access flags from the Field
                /// @return access flags
                shuriken::dex::TYPES::access_flags get_flags() {
                    return flags;
                }

                /// @brief Those fields that are static contains an initial value
                /// @param initial_value initial value for the field
                void set_initial_value(EncodedArray* initial_value) {
                    this->initial_value = initial_value;
                }

                /// @brief Get the pointer to the initial value
                /// @return EncodedArray of initial values
                const EncodedArray* get_initial_value() const {
                    return initial_value;
                }

                /// @brief Get the pointer to the initial value
                /// @return EncodedArray of initial values
                EncodedArray* get_initial_value() {
                    return initial_value;
                }
            };

            /// @brief Structure with information about the catched exception
            struct EncodedTypePair {
                /// @brief Type catched by the exception
                DVMType * type;
                /// @brief idx where the exception is catched
                std::uint64_t idx;
            };

            /// @brief Information of catch handlers
            class EncodedCatchHandler {
            public:
                using handler_pairs_t = std::vector<EncodedTypePair>;
                using it_handler_pairs = iterator_range<handler_pairs_t::iterator>;
            private:
                /// @brief Size of the vector of EncodedTypePair
                /// if > 0 indicates the size of the handlers
                /// if == 0 there are no handlers nor catch_all_addr
                /// if < 0 no handlers and catch_all_addr is set
                std::int64_t size;
                /// @brief vector of encoded type pair
                handler_pairs_t handlers;
                /// @brief bytecode of the catch all-handler.
                /// This element is only present if size is non-positive.
                std::uint64_t catch_all_addr = 0;
                /// @brief Offset where the encoded catch handler is
                /// in the file
                std::uint64_t offset;
            public:
                /// @brief Constructor of EncodedCatchHandler
                EncodedCatchHandler() = default;
                /// @brief Destructor of EncodedCatchHandler
                ~EncodedCatchHandler() = default;

                /// @brief Parse all the encoded type pairs
                /// @param stream stream with DEX data
                /// @param types types for the EncodedTypePair
                void parse_encoded_catch_handler(common::ShurikenStream& stream,
                                                 DexTypes& types);

                /// @brief Check value of size to test if there are encodedtypepairs
                /// @return if there are explicit typed catches
                bool has_explicit_typed_catches() const {
                    if (size >= 0) return true; // user should check size of handlers
                    return false;
                }

                /// @brief Get the size of the EncodedCatchHandler
                /// @return value of size, refer to `size` documentation
                /// to check the possible values
                std::int64_t get_size() const {
                    return size;
                }

                /// @brief Return the value from catch_all_addr
                /// @return catch_all_addr value
                std::uint64_t get_catch_all_addr() const {
                    return catch_all_addr;
                }

                /// @brief Get the offset where encoded catch handler is
                /// @return offset of encoded catch handler
                std::uint64_t get_offset() const {
                    return offset;
                }

                /// @brief Get an iterator to the handle pairs
                /// @return iterator to handlers
                it_handler_pairs get_handle_pairs() {
                    return make_range(handlers.begin(), handlers.end());
                }
            };

            /// @brief Structure with the information from a
            /// Try code
#pragma pack(1)
            struct TryItem {
                std::uint32_t start_addr;   //! start address of block of code covered by this entry.
                //! Count of 16-bit code units to start of first.
                std::uint16_t insn_count;   //! number of 16-bit code units covered by this entry.
                std::uint16_t handler_off;  //! offset in bytes from starts of associated encoded_catch_handler_list
                //! to encoded_catch_handler for this entry.
            };
#pragma pack()

            /// @brief Save the information of the code from a Method
            class CodeItemStruct {
            public:
                /// @brief Structure with information about a method code
                struct code_item_struct_t {
                    std::uint16_t registers_size;       //! number of registers used in the code
                    std::uint16_t ins_size;             //! number of words of incoming arguments to the method
                    std::uint16_t outs_size;            //! number of words of outgoung arguments space required
                    //! for method invocation.
                    std::uint16_t tries_size;           //! number of TryItem, can be 0
                    std::uint32_t debug_info_off;       //! offset to debug_info_item
                    std::uint32_t insns_size;           //! size of instruction list
                };

                using try_items_t = std::vector<TryItem>;
                using it_try_items = iterator_range<try_items_t::iterator>;

                using encoded_catch_handlers_t = std::vector<std::unique_ptr<EncodedCatchHandler>>;
                using it_encoded_catch_handlers = iterator_range<encoded_catch_handlers_t::iterator>;

            private:
                /// @brief Information of code item
                code_item_struct_t code_item;
                /// @brief Vector with the bytecode of the instructions
                std::vector<std::uint8_t> instructions_raw;
                /// @brief Vector of try_item
                try_items_t try_items;
                /// @brief encoded catch handler offset for exception
                /// calculation
                std::uint64_t encoded_catch_handler_list_offset;
                /// @brief encoded catch handler size
                std::uint64_t encoded_catch_handler_size;
                /// @brief encoded_catch_handler list
                encoded_catch_handlers_t encoded_catch_handlers;
            public:
                /// @brief Constructor of CodeItemStruct
                CodeItemStruct() = default;
                /// @brief Destructor of CodeItemStruct
                ~CodeItemStruct() = default;

                /// @brief Parser for the CodeItemStruct
                /// @param stream DEX file where to read data
                /// @param types types of the DEX
                void parse_code_item_struct(common::ShurikenStream& stream,
                                            DexTypes& types);

                /// @brief Get the number of registers used in a method
                /// @return number of registers
                std::uint16_t get_registers_size() const {
                    return code_item.registers_size;
                }

                /// @brief Get the number of words incoming arguments to the method
                /// @return number of words incoming arguments
                std::uint16_t get_incomings_args() const {
                    return code_item.ins_size;
                }

                /// @brief Get the number of words outgoing argument space required by the code
                /// @return number of words outgoing argument space
                std::uint16_t get_outgoing_args() const {
                    return code_item.outs_size;
                }

                /// @brief Get the number of try items in the method
                /// @return number of try items
                std::uint16_t get_number_try_items() const {
                    return code_item.tries_size;
                }

                /// @brief Get the offset to the debug information
                /// @return offset to debug information
                std::uint16_t get_offset_to_debug_info() const {
                    return code_item.debug_info_off;
                }

                /// @brief Get size of the dalvik instructions (number of opcodes)
                /// @return size of dalvik instructions
                std::uint16_t get_instructions_size() const {
                    return code_item.insns_size;
                }

                /// @brief Get a constant access to the instructions in raw, an std::span
                /// will not allow the modification and it provides quick access.
                /// @return span to the bytecode
                std::span<std::uint8_t> get_bytecode() {
                    std::span bytecode{instructions_raw};
                    return bytecode;
                }

                /// @brief Get an iterator to the try items
                /// @return try items from the method
                it_try_items get_try_items() {
                    return make_range(try_items.begin(), try_items.end());
                }

                /// @brief Return the offset where encoded catch handler is read
                /// @return offset to encoded catch handler list
                std::uint64_t get_encoded_catch_handler_offset() {
                    return encoded_catch_handler_list_offset;
                }

                it_encoded_catch_handlers get_encoded_catch_handlers() {
                    return make_range(encoded_catch_handlers.begin(), encoded_catch_handlers.end());
                }
            };

            class EncodedMethod {
            private:
                /// @brief MethodID that represents this encoded method
                MethodID* method_id;
                /// @brief Access flags of the method
                shuriken::dex::TYPES::access_flags access_flags;
                /// @brief Code Item of the method
                std::unique_ptr<CodeItemStruct> code_item;
            public:
                /// @brief Constructor of Encoded method
                /// @param method_id method of the current encoded method
                /// @param access_flags access flags of access of the method
                EncodedMethod(MethodID* method_id, shuriken::dex::TYPES::access_flags access_flags)
                        : method_id(method_id), access_flags(access_flags)
                {}

                /// @brief Destructor of Encoded method
                ~EncodedMethod() = default;

                /// @brief Parse the encoded method, this will parse the code item
                /// @param stream stream with DEX file
                /// @param code_off offset where code item struct
                /// @param types types from the DEX
                void parse_encoded_method(common::ShurikenStream& stream,
                                          std::uint64_t code_off,
                                          DexTypes& types);

                /// @brief Get a constant pointer to the MethodID of the method
                /// @return constant pointer to the MethodID
                const MethodID* getMethodID() const {
                    return method_id;
                }

                /// @brief Get a pointer to the MethodID of the encoded method
                /// @return pointer to the MethodID
                MethodID* getMethodID() {
                    return method_id;
                }

                shuriken::dex::TYPES::access_flags get_flags() {
                    return access_flags;
                }

                /// @brief Get the code item from the encoded method
                /// @return constant pointer to code item
                const CodeItemStruct* get_code_item() const
                {
                    return code_item.get();
                }

                /// @brief Get the code item from the encoded method
                /// @return reference to code item
                CodeItemStruct* get_code_item()
                {
                    return code_item.get();
                }
            };
        }
    }
}

#endif //SHURIKENLIB_DEX_ENCODED_H