//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file core-api-test.c
// @brief Test for the Core API in C of the project

#include "shuriken/api/C/shuriken_core.h"
#include "shuriken/api/C/shuriken_core_data.h"
#include "dex-files-folder.inc"

#include <iostream>


const char *file = DEX_FILES_FOLDER
        "test_zip.apk";

int main() {
    hApkContext apk_context = parse_apk(file, TRUE);

    int number_of_dex_files = get_number_of_dex_files(apk_context);

    std::cout << "Number of dex files: " << number_of_dex_files << '\n';

    for (int i = 0; i < number_of_dex_files; i++) {
        const char * dex_file = get_dex_file_by_index(apk_context, i);

        int number_of_classes = get_number_of_classes_for_dex_file(apk_context, dex_file);

        std::cout << "Dex file: " << dex_file
                  << ", number of classes: " << number_of_classes
                  << '\n';

        for (int j = 0; j < number_of_classes; j++) {
            hdvmclass_t * clazz = get_hdvmclass_from_dex_by_index(apk_context, dex_file, j);

            std::cout << "Class name: " << clazz->class_name << '\n';
        }
    }

    destroy_apk(apk_context);
}