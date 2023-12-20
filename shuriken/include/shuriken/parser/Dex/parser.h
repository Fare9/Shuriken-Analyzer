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

            public:
                /// @brief Default constructor of the java
                Parser() = default;
                /// @brief Default destructor of the java
                ~Parser() = default;

                /// @brief parse the dex file from the stream
                /// @param stream stream from where to retrieve the dex data
                void parse_dex(common::ShurikenStream& stream);


            };

        }
    }
}

#endif //SHURIKENLIB_PARSER_H
