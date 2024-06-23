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

#include "shuriken/common/Dex/dvm_types.h"
#include "shuriken/common/iterator_range.h"
#include "shuriken/common/shurikenstream.h"
#include "shuriken/parser/Dex/dex_fields.h"
#include "shuriken/parser/Dex/dex_methods.h"
#include "shuriken/parser/Dex/dex_strings.h"

#include <iostream>
#include <memory>
#include <span>
#include <variant>
#include <vector>

namespace shuriken::parser::dex {
    // Forward declaration needed
    class EncodedValue;

    /// @brief Information of an array with encoded values
    class EncodedArray {
    public:
        using encoded_values_t = std::vector<std::unique_ptr<EncodedValue>>;
        using encoded_values_s_t = std::vector<std::reference_wrapper<const EncodedValue>>;
        using it_encoded_value = iterator_range<encoded_values_t::iterator>;
        using it_const_encoded_value = iterator_range<
                const encoded_values_t::iterator>;

    private:
        /// @brief encoded values of the array
        encoded_values_t values;

        encoded_values_s_t values_s;

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
        void parse_encoded_array(common::ShurikenStream &stream,
                                 DexTypes &types,
                                 DexStrings &strings);

        size_t get_encodedarray_size() const;

        it_encoded_value get_encoded_values();

        it_const_encoded_value get_encoded_values_const();

        encoded_values_s_t &get_encoded_values_vector();
    };

    /// @brief Annotation element with value and a name
    /// this is contained in the EncodedAnnotation class
    class AnnotationElement {
    private:
        /// @brief name of the annotation element
        std::string_view name;
        /// @brief Value of the annotation
        std::unique_ptr<EncodedValue> value;

    public:
        /// @brief Constructor of the annotation element
        /// @param name name of the annotation
        /// @param value value of the annotation
        AnnotationElement(std::string_view name,
                          std::unique_ptr<EncodedValue> value);

        ~AnnotationElement() = default;

        std::string_view get_name() const;

        EncodedValue *get_value();
    };

    /// @brief Class to parse and create a vector of
    /// Annotations
    class EncodedAnnotation {
    public:
        using annotation_elements_t = std::vector<std::unique_ptr<AnnotationElement>>;
        using annotation_elements_s_t = std::vector<std::reference_wrapper<const AnnotationElement>>;
        using it_annotation_elements = iterator_range<annotation_elements_t::iterator>;
        using it_const_annotation_elements = iterator_range<
                const annotation_elements_t::iterator>;

    private:
        /// @brief Type of the annotation
        DVMType *type;
        /// @brief Array of annotation elements
        annotation_elements_t annotations;

        annotation_elements_s_t annotations_s;

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
        void parse_encoded_annotation(common::ShurikenStream &stream,
                                      DexTypes &types,
                                      DexStrings &strings);

        /// @brief Get the type of the annotations
        /// @return annotations type
        DVMType *get_annotation_type();

        /// @brief Get the number of annotations
        /// @return number of annotations
        size_t get_number_of_annotations() const;

        it_annotation_elements get_annotations();

        it_const_annotation_elements get_annotations_const();

        annotation_elements_s_t &get_annotations_vector();

        /// @brief Get an annotation element by position
        /// @param pos position to retrieve
        /// @return pointer to AnnotationElement
        AnnotationElement *get_annotation_by_pos(std::uint32_t pos);
    };

    /// @brief encoded piece of (nearly) arbitrary hierarchically structured data.
    class EncodedValue {
        using data_buffer_t = std::vector<std::uint8_t>;
        using it_data_buffer = iterator_range<data_buffer_t::iterator>;

    private:
        /// @brief Format of the encoded value
        shuriken::dex::TYPES::value_format format;
        /// @brief have a vector of uint8_t for normal types
        /// @brief an encoded array in case the type is an array
        /// @brief an encoded annotation in case the type is an annotation
        std::variant<data_buffer_t,
                     std::unique_ptr<EncodedArray>,
                     std::unique_ptr<EncodedAnnotation>>
                value;

    public:
        /// @brief Constructor of encoded value, default constructor
        EncodedValue() =
                default;
        /// @brief Destructor of encoded value
        ~EncodedValue() =
                default;

        void parse_encoded_value(common::ShurikenStream &stream,
                                 DexTypes &types,
                                 DexStrings &strings);

        shuriken::dex::TYPES::value_format get_value_format() const;

        it_data_buffer get_data_buffer();

        EncodedArray *get_array_data();

        EncodedAnnotation *get_annotation_data();

        std::int32_t convert_data_to_int();

        std::int64_t convert_data_to_long();

        std::uint8_t convert_data_to_byte();

        std::int16_t convert_data_to_short();

        double convert_data_to_double();

        float convert_data_to_float();

        std::uint16_t convert_data_to_char();
    };

    /// @brief encoded field with information about the initial values
    class EncodedField {
    private:
        /// @brief FieldID of the EncodedField
        FieldID *field_idx;
        /// @brief access flags for the field
        shuriken::dex::TYPES::access_flags flags;
        /// @brief Initial Value
        EncodedArray *initial_value;

    public:
        /// @brief Constructor of an encoded field
        /// @param field_idx FieldID for the encoded field
        /// @param flags
        EncodedField(FieldID *field_idx, shuriken::dex::TYPES::access_flags flags);

        /// @brief Destructor of Encoded Field
        ~EncodedField() = default;

        /// @brief Get a constant pointer to the FieldID
        /// @return constant pointer to the FieldID
        const FieldID *get_field() const;

        /// @brief Get a pointer to the FieldID
        /// @return pointer to the FieldID
        FieldID *get_field();

        /// @brief Get the access flags from the Field
        /// @return access flags
        shuriken::dex::TYPES::access_flags get_flags();

        /// @brief Those fields that are static contains an initial value
        /// @param initial_value initial value for the field
        void set_initial_value(EncodedArray *initial_value);

        /// @brief Get the pointer to the initial value
        /// @return EncodedArray of initial values
        const EncodedArray *get_initial_value() const;

        /// @brief Get the pointer to the initial value
        /// @return EncodedArray of initial values
        EncodedArray *get_initial_value();
    };

    /// @brief Structure with information about the catched exception
    struct EncodedTypePair {
        /// @brief Type catched by the exception
        DVMType *type;
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
        void parse_encoded_catch_handler(common::ShurikenStream &stream,
                                         DexTypes &types);

        /// @brief Check value of size to test if there are encodedtypepairs
        /// @return if there are explicit typed catches
        bool has_explicit_typed_catches() const;

        /// @brief Get the size of the EncodedCatchHandler
        /// @return value of size, refer to `size` documentation
        /// to check the possible values
        std::int64_t get_size() const;

        /// @brief Return the value from catch_all_addr
        /// @return catch_all_addr value
        std::uint64_t get_catch_all_addr() const;

        /// @brief Get the offset where encoded catch handler is
        /// @return offset of encoded catch handler
        std::uint64_t get_offset() const;

        /// @brief Get an iterator to the handle pairs
        /// @return iterator to handlers
        it_handler_pairs get_handle_pairs();
    };

    /// @brief Structure with the information from a
    /// Try code
#pragma pack(1)
    struct TryItem {
        std::uint32_t start_addr;//! start address of block of code covered by this entry.
        //! Count of 16-bit code units to start of first.
        std::uint16_t insn_count; //! number of 16-bit code units covered by this entry.
        std::uint16_t handler_off;//! offset in bytes from starts of associated encoded_catch_handler_list
        //! to encoded_catch_handler for this entry.
    };
#pragma pack()

    /// @brief Save the information of the code from a Method
    class CodeItemStruct {
    public:
        /// @brief Structure with information about a method code
        struct code_item_struct_t {
            std::uint16_t registers_size;//! number of registers used in the code
            std::uint16_t ins_size;      //! number of words of incoming arguments to the method
            std::uint16_t outs_size;     //! number of words of outgoung arguments space required
            //! for method invocation.
            std::uint16_t tries_size;    //! number of TryItem, can be 0
            std::uint32_t debug_info_off;//! offset to debug_info_item
            std::uint32_t insns_size;    //! size of instruction list
        };

        using try_items_t = std::vector<TryItem>;
        using it_try_items = iterator_range<try_items_t::iterator>;

        using encoded_catch_handlers_t = std::vector<std::unique_ptr<EncodedCatchHandler>>;
        using encoded_catch_handlers_s_t = std::vector<std::reference_wrapper<const EncodedCatchHandler>>;
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

        encoded_catch_handlers_s_t encoded_catch_handlers_s;

    public:
        /// @brief Constructor of CodeItemStruct
        CodeItemStruct() = default;
        /// @brief Destructor of CodeItemStruct
        ~CodeItemStruct() = default;

        /// @brief Parser for the CodeItemStruct
        /// @param stream DEX file where to read data
        /// @param types types of the DEX
        void parse_code_item_struct(common::ShurikenStream &stream,
                                    DexTypes &types);

        /// @brief Get the number of registers used in a method
        /// @return number of registers
        std::uint16_t get_registers_size() const;

        /// @brief Get the number of words incoming arguments to the method
        /// @return number of words incoming arguments
        std::uint16_t get_incomings_args() const;

        /// @brief Get the number of words outgoing argument space required by the code
        /// @return number of words outgoing argument space
        std::uint16_t get_outgoing_args() const;

        /// @brief Get the number of try items in the method
        /// @return number of try items
        std::uint16_t get_number_try_items() const;

        /// @brief Get the offset to the debug information
        /// @return offset to debug information
        std::uint16_t get_offset_to_debug_info() const;

        /// @brief Get size of the dalvik instructions (number of opcodes)
        /// @return size of dalvik instructions
        std::uint16_t get_instructions_size() const;

        /// @brief Get a constant access to the instructions in raw, an std::span
        /// will not allow the modification and it provides quick access.
        /// @return span to the bytecode
        std::span<std::uint8_t> get_bytecode();

        /// @brief Get an iterator to the try items
        /// @return try items from the method
        it_try_items get_try_items();

        /// @brief Return the offset where encoded catch handler is read
        /// @return offset to encoded catch handler list
        std::uint64_t get_encoded_catch_handler_offset();

        it_encoded_catch_handlers get_encoded_catch_handlers();

        encoded_catch_handlers_s_t get_encoded_catch_handlers_vector();
    };

    class EncodedMethod {
    private:
        /// @brief MethodID that represents this encoded method
        MethodID *method_id;
        /// @brief Access flags of the method
        shuriken::dex::TYPES::access_flags access_flags;
        /// @brief Code Item of the method
        std::unique_ptr<CodeItemStruct> code_item;

    public:
        /// @brief Constructor of Encoded method
        /// @param method_id method of the current encoded method
        /// @param access_flags access flags of access of the method
        EncodedMethod(MethodID *method_id, shuriken::dex::TYPES::access_flags access_flags);

        /// @brief Destructor of Encoded method
        ~EncodedMethod() = default;

        /// @brief Parse the encoded method, this will parse the code item
        /// @param stream stream with DEX file
        /// @param code_off offset where code item struct
        /// @param types types from the DEX
        void parse_encoded_method(common::ShurikenStream &stream,
                                  std::uint64_t code_off,
                                  DexTypes &types);

        /// @brief Get a constant pointer to the MethodID of the method
        /// @return constant pointer to the MethodID
        const MethodID *getMethodID() const;

        /// @brief Get a pointer to the MethodID of the encoded method
        /// @return pointer to the MethodID
        MethodID *getMethodID();

        shuriken::dex::TYPES::access_flags get_flags();

        /// @brief Get the code item from the encoded method
        /// @return constant pointer to code item
        const CodeItemStruct *get_code_item() const;

        /// @brief Get the code item from the encoded method
        /// @return reference to code item
        CodeItemStruct *get_code_item();
    };
} // namespace shuriken::parser::dex

#endif//SHURIKENLIB_DEX_ENCODED_H