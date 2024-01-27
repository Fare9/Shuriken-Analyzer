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

// header data
uint8_t magic[] = {'d', 'e', 'x', '\n', '0', '3', '5', '\0'};
int32_t checksum = 0xe4eefae3;
uint32_t file_size = 1624;
uint32_t header_size = 112;

uint32_t link_size = 0;
uint32_t link_off = 0;
uint32_t string_ids_size = 33;
uint32_t string_ids_off = 112;
uint32_t type_ids_size = 9;
uint32_t type_ids_off = 244;
uint32_t proto_ids_size = 7;
uint32_t proto_ids_off = 280;
uint32_t field_ids_size = 3;
uint32_t field_ids_off = 364;
uint32_t method_ids_size = 10;
uint32_t method_ids_off = 388;
uint32_t class_defs_size = 1;
uint32_t class_defs_off = 468;

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

void check_header(h_dex_header_t* dex_header);
void check_strings(hDexParser parser);
void check_types(hDexParser parser);
void check_methods(hDexParser parser);
void check_methods_list(hDexParser parser);
                            
int
main(int argc, char *argv[]) {
    hDexParser dexParser = parse_dex(file);
    h_dex_header_t* dex_header = get_dex_header(dexParser);

    check_header(dex_header);
    check_strings(dexParser);
    check_types(dexParser);
    check_methods(dexParser);
    destroy_dex(dexParser);
    return 0;
}

void check_header(h_dex_header_t* dex_header) {
    assert(memcmp(static_cast<const void*>(magic),
                  static_cast<const void*>(dex_header->magic),
                  sizeof(magic)) == 0 &&
           "Error header magic is incorrect");
    assert(checksum == dex_header->checksum && "Error checksum incorrect");
    assert(file_size == dex_header->file_size && "Error file_size incorrect");
    assert(header_size == dex_header->header_size && "Error header_size incorrect");
    assert(link_size == dex_header->link_size && "Error link_size incorrect");
    assert(link_off == dex_header->link_off && "Error link_off incorrect");
    assert(string_ids_size == dex_header->string_ids_size && "Error string_ids_size incorrect");
    assert(string_ids_off == dex_header->string_ids_off && "Error string_ids_off incorrect");
    assert(type_ids_size == dex_header->type_ids_size && "Error type_ids_size incorrect");
    assert(type_ids_off == dex_header->type_ids_off && "Error type_ids_off incorrect");
    assert(proto_ids_size == dex_header->proto_ids_size && "Error proto_ids_size incorrect");
    assert(proto_ids_off == dex_header->proto_ids_off && "Error proto_ids_off incorrect");
    assert(field_ids_size == dex_header->field_ids_size && "Error field_ids_size incorrect");
    assert(field_ids_off == dex_header->field_ids_off && "Error field_ids_off incorrect");
    assert(method_ids_size == dex_header->method_ids_size && "Error method_ids_size incorrect");
    assert(method_ids_off == dex_header->method_ids_off && "Error method_ids_off incorrect");
    assert(class_defs_size == dex_header->class_defs_size && "Error class_defs_size incorrect");
    assert(class_defs_off == dex_header->class_defs_off && "Error class_defs_off incorrect");
}

void check_strings(hDexParser parser) {
    size_t n_of_strings = get_number_of_strings(parser);
    assert(n_of_strings == 33 && "Number of strings is incorrect");
    for (size_t i = 0; i < n_of_strings; i++) {
        const char* str = get_string_by_id(parser, i);
        assert(strcmp(strs[i], str) == 0 && "Error string is incorrect");
    }
}

void check_types(hDexParser parser) {
    size_t n_of_types = get_number_of_types(parser);
    for (size_t i = 0; i < n_of_types; i++) {
        hdvmtype_t * t = get_type_by_id(parser, i);
        printf("raw type: %s, type: %d\n", t->raw_type, t->type);
        destroy_type(t);
    }
}

void check_methods(hDexParser parser) {
    size_t nr_of_methods = get_number_of_methods(parser);
    printf("found: %lu methods\n", nr_of_methods);
}


void check_methods_list(hDexParser parser) {
    hdvmmethod_t** methods = (hdvmmethod_t**)get_methods_list(parser);
    size_t nr_of_methods = get_number_of_methods(parser);
    uint16_t i;
    for (i=0; i < nr_of_methods - 1; ++i) {
        printf( "method name: %s - method pretty name %s - method class %s - method prototype %s", methods[i]->name, methods[i]->pretty_name, methods[i]->belonging_class, methods[i]->protoId);
    }
}

void check_classes_list(hDexParser parser) {
    hdex_class_t** classes = (hdex_class_t**)get_classes(parser);
    size_t nr_of_classes = get_number_of_classes(parser);
    uint16_t i;
    for (i=0; i < nr_of_classes - 1; ++i) {
        printf( "class name: %s - super class name %s - source file %s", classes[i]->class_name, classes[i]->super_class, classes[i]->source_file );
    }
}
