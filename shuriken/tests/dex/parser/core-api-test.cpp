//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file core-api-test.c
// @brief Test for the Core API in C of the project

#include "shuriken/api/C/shuriken_core.h"
#include "dex-files-folder.inc"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const char *file = DEX_FILES_FOLDER
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


struct method_struct {
    const char *dalvik_name;
    uint16_t access_flags;
};

struct field_struct {
    const char *name;
    const char *type;
    uint16_t access_flags;
};

struct class_struct {
    const char *name;
    const char *super_class_name;
    uint16_t access_flags;
};

struct class_struct classes[] = {
        {.name = "DexParserTest",
         .super_class_name = "java.lang.Object",
         .access_flags = 1},
};

struct method_struct direct_methods[] = {
        {.dalvik_name = "LDexParserTest;-><init>()V",
         .access_flags = 1},
        {.dalvik_name = "LDexParserTest;->calculateSum(II)I",
         .access_flags = 2},
        {.dalvik_name = "LDexParserTest;->main([Ljava/lang/String;)V",
         .access_flags = 9},
        {.dalvik_name = "LDexParserTest;->printMessage()V",
         .access_flags = 2}};

struct method_struct virtual_methods[] = {};

struct field_struct instance_fields[] = {
        {.name = "field1",
         .type = "I",
         .access_flags = 2},
        {.name = "field2",
         .type = "Ljava/lang/String;",
         .access_flags = 2}};

struct field_struct static_fields[] = {};


void check_strings(hDexContext parser);
void check_classes_list(hDexContext parser);

int main() {
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
        [[maybe_unused]] const char *str = get_string_by_id(parser, i);
        assert(strcmp(strs[i], str) == 0 && "Error string is incorrect");
    }
}

void check_classes_list(hDexContext parser) {
    size_t nr_of_classes = get_number_of_classes(parser);
    uint16_t i;
    for (i = 0; i < nr_of_classes; ++i) {
        auto class_ = get_class_by_id(parser, i);
        printf("class name: %s - super class name %s - source file %s - access flags %u\n", class_->class_name, class_->super_class, class_->source_file, class_->access_flags);

        assert(strcmp(classes[i].name, class_->class_name) == 0 &&
               "Error, class name is not correct");
        assert(strcmp(classes[i].super_class_name, class_->super_class) == 0 &&
               "Error, class super class name is not correct");
        assert(classes[i].access_flags == class_->access_flags &&
               "Error, class access flags are not correct");

        printf("Direct methods:\n");
        for (uint32_t j = 0; j < class_->direct_methods_size; j++) {
            assert(strcmp(direct_methods[j].dalvik_name, class_->direct_methods[j].dalvik_name) == 0 &&
                   "Error, method name is not correct");
            assert(direct_methods[j].access_flags == class_->direct_methods[j].access_flags &&
                   "Error, method access flag are not correct");
            printf("Dalvik name %s - access flags %u\n", class_->direct_methods[j].dalvik_name, class_->direct_methods[j].access_flags);
        }

        printf("Virtual methods:\n");
        for (uint32_t j = 0; j < class_->virtual_methods_size; j++) {
            assert(strcmp(virtual_methods[j].dalvik_name, class_->virtual_methods[j].dalvik_name) == 0 &&
                   "Error, method name is not correct");
            assert(virtual_methods[j].access_flags == class_->virtual_methods[j].access_flags &&
                   "Error, method access flag are not correct");
            printf("Dalvik name %s - access flags %u\n", class_->virtual_methods[j].dalvik_name, class_->virtual_methods[j].access_flags);
        }

        printf("Instance fields:\n");
        for (uint32_t j = 0; j < class_->instance_fields_size; j++) {
            assert(strcmp(instance_fields[j].name, class_->instance_fields[j].name) == 0 &&
                   "Error, field name is not correct");
            assert(strcmp(instance_fields[j].type, class_->instance_fields[j].type_value) == 0 &&
                   "Error, field type is not correct");
            assert(instance_fields[j].access_flags == class_->instance_fields[j].access_flags &&
                   "Error, field access flags are not correct");
            printf("Field name %s - field type %s - access flags %u\n", class_->instance_fields[j].name, class_->instance_fields[j].type_value, class_->instance_fields[j].access_flags);
        }

        printf("Static fields:\n");
        for (uint32_t j = 0; j < class_->static_fields_size; j++) {
            assert(strcmp(static_fields[j].name, class_->static_fields[j].name) == 0 &&
                   "Error, field name is not correct");
            assert(strcmp(static_fields[j].type, class_->static_fields[j].type_value) == 0 &&
                   "Error, field type is not correct");
            assert(static_fields[j].access_flags == class_->static_fields[j].access_flags &&
                   "Error, field access flags are not correct");
            printf("Field name %s - field type %s - access flags %u\n", class_->static_fields[j].name, class_->static_fields[j].type_value, class_->static_fields[j].access_flags);
        }
    }
}
