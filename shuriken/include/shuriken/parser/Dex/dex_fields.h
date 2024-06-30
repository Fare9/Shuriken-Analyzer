//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file fields.h
// @brief Manage all the data from the fields from the DEX files.

#ifndef SHURIKEN_ANALYZER_FIELDS_H
#define SHURIKEN_ANALYZER_FIELDS_H

#include "shuriken/common/deref_iterator_range.h"
#include "shuriken/common/iterator_range.h"
#include "shuriken/common/shurikenstream.h"
#include "shuriken/parser/Dex/dex_strings.h"
#include "shuriken/parser/Dex/dex_types.h"

#include <memory>
#include <vector>

namespace shuriken::parser::dex {
    class EncodedField;

    /// @brief Class that represents a Field in Dalvik, Fields are variables
    /// that belong to an object. FieldID contains the basic data from that
    /// field
    class FieldID {
    private:
        /// @brief Class to which the field belongs
        DVMType *class_;
        /// @brief Field type
        DVMType *type_;
        /// @brief Field name
        std::string_view name_;
        /// @brief Pretty name
        std::string pretty_name;
        /// @brief for analysis of instructions
        EncodedField *encoded_field;

    public:
        /// @brief Constructor of FieldID
        FieldID(DVMType *class_, DVMType *type_, std::string_view name_);

        /// @brief Destructor of FieldID, default one
        ~FieldID() = default;

        /// @return constant pointer to class the field belongs to
        const DVMType *field_class() const;

        /// @return pointer to class the field belongs to
        DVMType *field_class();

        /// @return constant pointer to the type of the field
        const DVMType *field_type() const;

        /// @return pointer to the type of the field
        DVMType *field_type();

        /// @return name of the field
        std::string_view field_name() const;

        /// @brief Return a formatted version of the field including the
        /// class, the name and its type.
        /// @return prettyfied version of the field
        std::string_view pretty_field();

        /// @brief To refer to an encoded field, setter of EncodedField pointer.
        void set_encoded_field(EncodedField *field);

        /// @return pointer to EncodedField related to FieldID
        EncodedField *get_encoded_field();
    };

    inline bool operator==(const FieldID &lhs, const FieldID &rhs) {
        if (*(lhs.field_class()) == *(rhs.field_class()) &&
            *(lhs.field_type()) == *(rhs.field_type()) &&
            lhs.field_name() == rhs.field_name())
            return true;
        return false;
    }

    inline bool operator!=(const FieldID &lhs, const FieldID &rhs) {
        return !(lhs == rhs);
    }

    class DexFields {
    public:
        using field_ids_t = std::vector<std::unique_ptr<FieldID>>;
        using field_ids_s_t = std::vector<std::reference_wrapper<FieldID>>;
        using it_field_ids = deref_iterator_range<field_ids_s_t>;
        using it_const_field_ids = deref_iterator_range<const field_ids_s_t>;

    private:
        /// @brief List of FieldIDs
        field_ids_t fields;
        /// @brief Reference to the previous objects in the vector
        field_ids_s_t fields_s;

    public:
        /// @brief Default constructor for fields
        DexFields() = default;
        /// @brief Default destructor for fields
        ~DexFields() = default;

        /// @brief Function for parsing all the fields from
        /// a dex file
        /// @param stream file where to read the fields
        /// @param types types to retrieve information
        /// @param strings strings to retrieve information
        void parse_fields(
                common::ShurikenStream &stream,
                DexTypes &types,
                DexStrings &strings,
                std::uint32_t fields_offset,
                std::uint32_t n_of_fields);

        /// @return vector with constant references from the fields
        field_ids_s_t &get_all_fields();

        /// @brief Get an iterator for the fields
        /// @return fields iterator
        it_field_ids get_fields();

        /// @brief Get a constant iterator for the fields
        /// @return constant iterator for the fields
        it_const_field_ids get_fields_const();

        /// @brief Get a pointer to a field given its id
        /// @param id id from the FieldID
        /// @return pointer to a FieldID
        FieldID *get_field_by_id(std::uint32_t id);

        /// @brief Get an ID given a field
        /// @param field the field to look for
        /// @return an id of the field or -1
        std::int64_t get_id_by_field(FieldID *field);

        /// @brief Print the fields into an XML format.
        /// @param fos file where to dump it
        void to_xml(std::ofstream &fos);
    };
}// namespace shuriken::parser::dex

#endif//SHURIKEN_ANALYZER_FIELDS_H
