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

#include "shuriken/parser/Dex/dex_header.h"
#include "shuriken/parser/Dex/dex_mapitem.h"
#include "shuriken/parser/Dex/dex_strings.h"
#include "shuriken/parser/Dex/dex_types.h"
#include "shuriken/parser/Dex/dex_protos.h"
#include "shuriken/parser/Dex/dex_fields.h"
#include "shuriken/parser/Dex/dex_methods.h"

#include "shuriken/parser/Dex/dex_annotations.h"
#include "shuriken/parser/Dex/dex_encoded.h"
#include "shuriken/parser/Dex/dex_classes.h"

namespace shuriken {
    namespace parser {
        namespace dex {

            class Parser {
            private:
                /// @brief DexHeader of the DEX file
                DexHeader header_;
                /// @brief Structure with information of the DEX file
                DexMapList maplist_;
                /// @brief DexStrings of the DEX file
                DexStrings strings_;
                /// @brief DexTypes of the DEX file
                DexTypes types_;
                /// @brief DexProtos of the DEX file
                DexProtos protos_;
                /// @brief DexFields of the DEX file
                DexFields fields_;
                /// @brief DexMethods of the DEX file
                DexMethods methods_;
                /// @brief DexClasses of the DEX file
                DexClasses classes_;

            public:
                /// @brief Default constructor of the java
                Parser() = default;
                /// @brief Default destructor of the java
                ~Parser() = default;

                /// @brief parse the dex file from the stream
                /// @param stream stream from where to retrieve the dex data
                void parse_dex(common::ShurikenStream& stream);

                DexHeader& get_header() {
                    return header_;
                }

                const DexHeader& get_header() const {
                    return header_;
                }

                DexMapList& get_maplist() {
                    return maplist_;
                }

                const DexMapList& get_maplist() const {
                    return maplist_;
                }

                DexStrings& get_strings() {
                    return strings_;
                }

                const DexStrings& get_strings() const {
                    return strings_;
                }

                DexTypes& get_types() {
                    return types_;
                }

                const DexTypes& get_types() const {
                    return types_;
                }

                DexProtos& get_protos() {
                    return protos_;
                }

                const DexProtos& get_protos() const {
                    return protos_;
                }

                DexFields& get_fields() {
                    return fields_;
                }

                const DexFields& get_fields() const {
                    return fields_;
                }

                DexMethods& get_methods() {
                    return methods_;
                }

                const DexMethods& get_methods() const {
                    return methods_;
                }

                DexClasses& get_classes() {
                    return classes_;
                }

                const DexClasses& get_classes() const {
                    return classes_;
                }
            };

        }
    }
}

#endif //SHURIKENLIB_PARSER_H
