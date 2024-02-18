//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file core-api-test.c
// @brief Test for the Core API in C of the project

#include "dex-files-folder.inc"
#include "shuriken/api/shuriken_parsers_core.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

const char *file = DEX_FILES_FOLDER \
                    "DexParserTest.dex";

/// strings
const char *strs[] = {" and ",
                     " is: ",
                     "<init>",
                     "DexParserTest.java",
                     "Field 1: ",
                     "Field 2: ",
                     "Hello, Dex Parser!",
                     "I",
                     "III",
                     "L",
                     "LDexParserTest;",
                     "LI",
                     "LL",
                     "Ljava/io/PrintStream;",
                     "Ljava/lang/Object;",
                     "Ljava/lang/String;",
                     "Ljava/lang/StringBuilder;",
                     "Ljava/lang/System;",
                     "Sum of ",
                     "This is a test message printed from DexParserTest class.",
                     "V",
                     "VL",
                     "[Ljava/lang/String;",
                     "append",
                     "calculateSum",
                     "field1",
                     "field2",
                     "main",
                     "out",
                     "printMessage",
                     "println",
                     "toString",
                     "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":1,\"version\":\"3.3.20-dev+aosp5\"}"};

void check_strings(hDexContext parser);
void check_classes_list(hDexContext parser);
                            
int
main(int argc, char *argv[]) {
    hDexContext dexParser = parse_dex(file);

    check_strings(dexParser);
    check_classes_list(dexParser);
    destroy_dex(dexParser);
    return 0;
}

void check_strings(hDexContext parser) {
    size_t n_of_strings = get_number_of_strings(parser);
    assert(n_of_strings == 33 && "Number of strings is incorrect");
    for (size_t i = 0; i < n_of_strings; i++) {
        const char* str = get_string_by_id(parser, i);
        assert(strcmp(strs[i], str) == 0 && "Error string is incorrect");
    }
}

void check_classes_list(hDexContext parser) {
    size_t nr_of_classes = get_number_of_classes(parser);
    uint16_t i;
    for (i=0; i < nr_of_classes; ++i) {
        auto class_ = get_class_by_id(parser, i);
        printf( "class name: %s - super class name %s - source file %s", class_->class_name, class_->super_class, class_->source_file );
    }
}
