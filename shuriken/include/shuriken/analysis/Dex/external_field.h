//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file external_field.h
// @brief This external field will be created for the analysis in those cases
// the field is in another dex or is not in the apk.

#ifndef SHURIKENPROJECT_EXTERNAL_FIELD_H
#define SHURIKENPROJECT_EXTERNAL_FIELD_H


#include "shuriken/common/Dex/dvm_types.h"


namespace shuriken::analysis::dex {
    class ExternalField {
    private:
        /// @brief name of the class
        std::string class_idx;

        /// @brief name of the method
        std::string name_idx;

        /// @brief type of the field
        std::string type;

        /// @brief pretty name of the field
        std::string pretty_name;

        shuriken::dex::TYPES::access_flags access_flags = shuriken::dex::TYPES::NONE;

    public:
        ExternalField(std::string_view class_idx, std::string_view name_idx, std::string_view type);

        ~ExternalField() = default;

        /// @brief Return the name of the class where the field is
        /// @return name of the class
        std::string_view get_class_idx() const;

        /// @brief Get the name of the external field
        /// @return name of the method
        std::string_view get_name_idx() const;

        /// @brief Get the type of the external field
        /// @return prototype of the method
        std::string_view get_type_idx() const;

        /// @brief Get a pretty printed version of the name
        /// that includes class name, name of the field
        /// @return pretty printed version of the name
        std::string_view pretty_field_name();

        /// @brief Get the access flags from the method
        /// @return NONE access flags
        shuriken::dex::TYPES::access_flags get_access_flags() const;
    };
}// namespace shuriken::analysis::dex

#endif//SHURIKENPROJECT_EXTERNAL_FIELD_H
