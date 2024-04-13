//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file external_class.h
// @brief A class for managing external classes that does not exist in
// current DEX or current apk file

#ifndef SHURIKENPROJECT_EXTERNAL_CLASS_H
#define SHURIKENPROJECT_EXTERNAL_CLASS_H

#include "shuriken/analysis/Dex/external_method.h"
#include "shuriken/parser/Dex/dex_encoded.h"
#include <iostream>
#include <vector>
#include <memory>

namespace shuriken {
    namespace analysis {
        namespace dex {
            class ExternalClass {
            private:
                /// @brief name of the external class
                std::string_view name;
                /// @brief Vector with all the external methods from the current class
                std::vector<ExternalMethod*> methods;
                /// @brief Vector of EncodedFields created through FieldID
                std::vector<std::unique_ptr<shuriken::parser::dex::EncodedField>> fields;
            public:
                ExternalClass(std::string_view name);

                ~ExternalClass() = default;

                /// @brief Get the name of the external class
                /// @return name of the class
                std::string_view get_name();

                /// @brief Get an iterator to the methods of the class
                /// @return iterator to methods
                iterator_range<std::vector<ExternalMethod*>::iterator> get_methods();

                /// @brief Get an iterator to the fields of this class
                /// @return iterator to fields
                iterator_range<
                        std::vector<std::unique_ptr<shuriken::parser::dex::EncodedField>>::iterator>
                get_fields();

                /// @brief Add an external method to the list of methods
                /// @param method new method of the class
                void add_external_method(ExternalMethod* method);

                /// @brief Add a new EncodedField to the class, we do not know if this
                /// is static or any other kind of field
                /// @param field FieldID object used to create the EncodedField
                void add_external_field(shuriken::parser::dex::FieldID* field);
            };
        }
    }
}

#endif //SHURIKENPROJECT_EXTERNAL_CLASS_H
