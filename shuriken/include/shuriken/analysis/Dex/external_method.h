//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file external_method.h
// @brief This external method will be created for the analysis in those cases
// the method is in another dex or is not in the apk.

#ifndef SHURIKENPROJECT_EXTERNAL_METHOD_H
#define SHURIKENPROJECT_EXTERNAL_METHOD_H

#include "shuriken/common/Dex/dvm_types.h"


namespace shuriken::analysis::dex {
    class ExternalMethod {
    private:
        /// @brief name of the class
        std::string class_idx;

        /// @brief name of the method
        std::string name_idx;

        /// @brief prototype of the method
        std::string proto_idx;

        /// @brief name that joins class+method+proto
        std::string pretty_name;

        shuriken::dex::TYPES::access_flags access_flags = shuriken::dex::TYPES::NONE;

    public:
        ExternalMethod(std::string_view class_idx, std::string_view name_idx, std::string_view proto_idx,
                       shuriken::dex::TYPES::access_flags access_flags);

        ~ExternalMethod() = default;

        /// @brief Return the name of the class where the method is
        /// @return name of the class
        std::string_view get_class_idx() const;

        /// @brief Get the name of the external method
        /// @return name of the method
        std::string_view get_name_idx() const;

        /// @brief Get the prototype of the external method
        /// @return prototype of the method
        std::string_view get_proto_idx() const;

        /// @brief Get a pretty printed version of the name
        /// that includes class name, name of the method
        /// and the prototype.
        /// @return pretty printed version of the name
        std::string_view pretty_method_name();

        /// @brief Get the access flags from the method
        /// @return NONE access flags
        shuriken::dex::TYPES::access_flags get_access_flags() const;
    };
}// namespace shuriken::analysis::dex


#endif//SHURIKENPROJECT_EXTERNAL_METHOD_H
