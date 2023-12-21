//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file parser.h
// @brief Parser for the DEX file, here we contain objects for all the other
// fields

#ifndef SHURIKENLIB_PARSER_H
#define SHURIKENLIB_PARSER_H

#include "shuriken/common/shurikenstream.h"

#include "shuriken/parser/Dex/header.h"
#include "shuriken/parser/Dex/strings.h"
#include "shuriken/parser/Dex/types.h"
#include "shuriken/parser/Dex/protos.h"
#include "shuriken/parser/Dex/fields.h"

namespace shuriken {
    namespace parser {
        namespace dex {

            class Parser {
            private:
                /// @brief Header of the DEX file
                Header header_;
                /// @brief Strings of the DEX file
                Strings strings_;
                /// @brief Types of the DEX file
                Types types_;
                /// @brief Protos of the DEX file
                Protos protos_;
                /// @brief Fields of the DEX file
                Fields fields_;

            public:
                /// @brief Default constructor of the java
                Parser() = default;
                /// @brief Default destructor of the java
                ~Parser() = default;

                /// @brief parse the dex file from the stream
                /// @param stream stream from where to retrieve the dex data
                void parse_dex(common::ShurikenStream& stream);

                Header& get_header() {
                    return header_;
                }

                const Header& get_header() const {
                    return header_;
                }

                Strings& get_strings() {
                    return strings_;
                }

                const Strings& get_strings() const {
                    return strings_;
                }

                Types& get_types() {
                    return types_;
                }

                const Types& get_types() const {
                    return types_;
                }

                Protos& get_protos() {
                    return protos_;
                }

                const Protos& get_protos() const {
                    return protos_;
                }

                Fields& get_fields() {
                    return fields_;
                }

                const Fields& get_fields() const {
                    return fields_;
                }
            };

        }
    }
}

#endif //SHURIKENLIB_PARSER_H
