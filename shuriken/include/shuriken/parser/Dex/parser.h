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
#include "shuriken/parser/Dex/mapitem.h"
#include "shuriken/parser/Dex/strings.h"
#include "shuriken/parser/Dex/types.h"
#include "shuriken/parser/Dex/protos.h"
#include "shuriken/parser/Dex/fields.h"
#include "shuriken/parser/Dex/methods.h"

#include "shuriken/parser/Dex/annotations.h"
#include "shuriken/parser/Dex/encoded.h"
#include "shuriken/parser/Dex/classes.h"

namespace shuriken {
    namespace parser {
        namespace dex {

            class Parser {
            private:
                /// @brief Header of the DEX file
                Header header_;
                /// @brief Structure with information of the DEX file
                MapList maplist_;
                /// @brief Strings of the DEX file
                Strings strings_;
                /// @brief Types of the DEX file
                Types types_;
                /// @brief Protos of the DEX file
                Protos protos_;
                /// @brief Fields of the DEX file
                Fields fields_;
                /// @brief Methods of the DEX file
                Methods methods_;
                /// @brief Classes of the DEX file
                Classes classes_;

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

                MapList& get_maplist() {
                    return maplist_;
                }

                const MapList& get_maplist() const {
                    return maplist_;
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

                Methods& get_methods() {
                    return methods_;
                }

                const Methods& get_methods() const {
                    return methods_;
                }

                Classes& get_classes() {
                    return classes_;
                }

                const Classes& get_classes() const {
                    return classes_;
                }
            };

        }
    }
}

#endif //SHURIKENLIB_PARSER_H
