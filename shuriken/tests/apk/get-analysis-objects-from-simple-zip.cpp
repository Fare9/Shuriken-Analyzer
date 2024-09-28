//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file get-analysis-objects-from-simple-zip.cpp
// @brief Core API test to check if the get analysis classes and methods work

#include "dex-files-folder.inc"
#include "shuriken/api/C/shuriken_core.h"
#include <iostream>
#include <cassert>

int main() {
    std::string zip_file = std::string(DEX_FILES_FOLDER) + "test_zip.apk";

    hApkContext apk_context = parse_apk(zip_file.c_str(), 1);

    for (int i = 0,
             n_of_dex_files = get_number_of_dex_files(apk_context);
         i < n_of_dex_files;
         i++) {
        const char * dex_file = get_dex_file_by_index(apk_context, i);

        for (int j = 0,
                n_of_classes = get_number_of_classes_for_dex_file(apk_context, dex_file);
             j < n_of_classes;
             j++) {
            hdvmclass_t * cls = get_hdvmclass_from_dex_by_index(apk_context, dex_file, j);

            [[maybe_unused]] hdvmclassanalysis_t * cls_analysis = get_analyzed_class_by_hdvmclass_from_apk(apk_context, cls);

            assert(cls_analysis != nullptr && "Error get_analyzed_class_by_hdvmclass_from_apk didn't work");

            [[maybe_unused]] hdvmclassanalysis_t *cls_analysis2 = get_analyzed_class_from_apk(apk_context, cls->class_name);

            assert(cls_analysis2 != nullptr && "Error get_analyzed_class_from_apk didn't work");

            assert(cls_analysis == cls_analysis2 && "Error, returned two different hdvmclassanalysis_t");

            for (int z = 0,
                     n_of_virtual_methods = cls->virtual_methods_size;
                    z < n_of_virtual_methods;
                    z++) {
                hdvmmethod_t * method = &cls->virtual_methods[z];

                [[maybe_unused]] hdvmmethodanalysis_t * method_analysis = get_analyzed_method_by_hdvmmethod_from_apk(apk_context, method);

                assert(method_analysis != nullptr && "Error get_analyzed_method_by_hdvmmethod_from_apk didn't work");

                [[maybe_unused]] hdvmmethodanalysis_t * method_analysis2 = get_analyzed_method_from_apk(apk_context, method->dalvik_name);

                assert(method_analysis2 != nullptr && "Error get_analyzed_method_from_apk didn't work");

                assert(method_analysis == method_analysis2 && "Error, returned two different hdvmmethodanalysis_t");
            }

            for (int z = 0,
                     n_of_direct_methods = cls->direct_methods_size;
                    z < n_of_direct_methods;
                    z++) {
                hdvmmethod_t * method = &cls->direct_methods[z];

                [[maybe_unused]] hdvmmethodanalysis_t * method_analysis = get_analyzed_method_by_hdvmmethod_from_apk(apk_context, method);

                assert(method_analysis != nullptr && "Error get_analyzed_method_by_hdvmmethod_from_apk didn't work");

                [[maybe_unused]] hdvmmethodanalysis_t * method_analysis2 = get_analyzed_method_from_apk(apk_context, method->dalvik_name);

                assert(method_analysis2 != nullptr && "Error get_analyzed_method_from_apk didn't work");

                assert(method_analysis == method_analysis2 && "Error, returned two different hdvmmethodanalysis_t");
            }
        }
    }

    destroy_apk(apk_context);
}