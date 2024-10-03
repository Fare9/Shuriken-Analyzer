//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file shuriken_parsers_core.h
// @brief Shim in C for accessing the different data from ShurikenLib

#ifndef SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
#define SHURIKENLIB_SHURIKEN_PARSERS_CORE_H

#ifdef __cplusplus
#if defined(_WIN32) || defined(__WIN32__)
#ifdef SHURIKENLIB_EXPORTS
#define SHURIKENCOREAPI __declspec(dllexport)
#else
#define SHURIKENCOREAPI __declspec(dllimport)
#endif
#else
#define SHURIKENCOREAPI extern "C"
#endif
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#else
#define SHURIKENCOREAPI
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#endif

#include "shuriken/api/C/shuriken_core_data.h"

extern "C" {

/// C - DEX part of the CORE API from ShurikenLib

///--------------------------- Parser API ---------------------------

/// @brief main method from the DEX Core API
/// it parses the DEX file and it retrieves a context object
/// @param filePath path to the DEX file to analyze
/// @return context object to obtain information from the DEX file
SHURIKENCOREAPI hDexContext parse_dex(const char *filePath);

/// @brief Since the context object use dynamic memory this method
/// will properly destroy the object.
/// @param context object to destroys
SHURIKENCOREAPI void destroy_dex(hDexContext context);

/// @brief Get the number of strings from the DEX file
/// @param context from the DEX file
/// @return number of strings
SHURIKENCOREAPI size_t get_number_of_strings(hDexContext context);

/// @brief get one of the strings by the id
/// @param context from where to retrieve the string
/// @param i id of the string to retrieve
/// @return string from the id
SHURIKENCOREAPI const char *get_string_by_id(hDexContext context, size_t i);

/// @brief Get the number of classes from the DEX file
/// @param context dex from where to retrieve the number of classes
/// @return number of classes
SHURIKENCOREAPI uint16_t get_number_of_classes(hDexContext context);

/// @brief Get a class structure given an ID
/// @param context DEX from where to retrieve the class
/// @param i id of the class to retrieve
/// @return class from the DEX file
SHURIKENCOREAPI hdvmclass_t *get_class_by_id(hDexContext context, uint16_t i);

/// @brief Get a class structure given a class name
/// @param context DEX from where to retrieve the class
/// @param class_name name of the class to retrieve
/// @return class from the DEX file
SHURIKENCOREAPI hdvmclass_t *get_class_by_name(hDexContext context, const char *class_name);

/// @brief Get a method structure given a full dalvik name.
/// @param context DEX from where to retrieve the method
/// @param method_name LclassName;->methodName(parameters)RetType
/// @return pointer to hdvmmethod_t, null if the method does not exist
SHURIKENCOREAPI hdvmmethod_t *get_method_by_name(hDexContext context, const char *method_name);


///--------------------------- Disassembler API ---------------------------


/// @brief Disassemble a DEX file and generate an internal DexDisassembler
/// @param context DEX to disassemble the methods
SHURIKENCOREAPI void disassemble_dex(hDexContext context);

/// @brief Get a method structure given a full dalvik name.
/// @param context DEX from where to retrieve the method
/// @param method_name LclassName;->methodName(parameters)RetType
/// @return pointer to a disassembled method
SHURIKENCOREAPI dvmdisassembled_method_t *get_disassembled_method(hDexContext context, const char *method_name);

///--------------------------- Analysis API ---------------------------

/// @brief Create a DEX analysis object inside of context, for obtaining the analysis
/// user must also call `analyze_classes`.
/// @param context context from the CORE API
/// @param create_xrefs boolean to generate or not xrefs (analysis takes longer)
SHURIKENCOREAPI void create_dex_analysis(hDexContext context, char create_xrefs);

/// @brief Analyze the classes, add fields and methods into the classes, optionally
/// create the xrefs.
/// @param context context from the CORE API
SHURIKENCOREAPI void analyze_classes(hDexContext context);


/// @brief Obtain one hdvmclassanalysis_t given its hdvmclass_t
/// @param context DEX context from the CORE API
/// @param class_ hdvmclass_t to get its analysis
SHURIKENCOREAPI hdvmclassanalysis_t *get_analyzed_class_by_hdvmclass(hDexContext context, hdvmclass_t *class_);

/// @brief Obtain one hdvmclassanalysis_t given its name.
/// @param context DEX context from the CORE API
/// @param class_name name of the class to retrieve
SHURIKENCOREAPI hdvmclassanalysis_t *get_analyzed_class(hDexContext context, const char *class_name);

/// @brief Obtain one hdvmmethodanalysis_t given its hdvmmethod_t
/// @param context DEX context from the CORE API
/// @param method hdvmmethod_t to get its analysis
SHURIKENCOREAPI hdvmmethodanalysis_t *get_analyzed_method_by_hdvmmethod(hDexContext context, hdvmmethod_t *method);

/// @brief Obtain one hdvmmethodanalysis_t given its name
/// @param context DEX context from the CORE API
/// @param method_full_name dalvik name of the method
SHURIKENCOREAPI hdvmmethodanalysis_t *get_analyzed_method(hDexContext context, const char *method_full_name);

/// C - APK part of the CORE API from ShurikenLib

///--------------------------- Parser API ---------------------------

/// @brief main method from the APK Core API
/// it parses the APK file and it retrieves a context object
/// @param filePath path to the APK file to analyze
/// @param create_xref `1` to create xrefs, `0` to avoid creating xrefs
/// @return context object to obtain information from the APK file
SHURIKENCOREAPI hApkContext parse_apk(const char *filePath, boolean_e create_xref);

/// @brief Since the context object use dynamic memory this method
/// will properly destroy the object.
/// @param context object to destroys
SHURIKENCOREAPI void destroy_apk(hApkContext context);

/// @brief APKs contain a number of DEX files with the classes,
/// with this you retrieve the number of those dex files
/// @return number of dex files in the APK
SHURIKENCOREAPI int get_number_of_dex_files(hApkContext context);

/// @brief Given an idx retrieve the name of one of the dex files
/// @param idx index of the dex file to retrieve
/// @return a string with the path of the dex file in the apk
SHURIKENCOREAPI const char * get_dex_file_by_index(hApkContext context, unsigned int idx);

/// @brief Every dex file contains a number of classes, retrieve it by
/// the name of the dex file
/// @param dex_file file to retrieve the number of classes
/// @return number of classes in the dex file
SHURIKENCOREAPI int get_number_of_classes_for_dex_file(hApkContext context, const char * dex_file);

/// @brief retrieve one of the hdvmclass_t from a dex file
/// @param dex_file dex file from where to retrieve the class
/// @param idx index of the class to retrieve
/// @return hdvmclass_t in the given position
SHURIKENCOREAPI hdvmclass_t * get_hdvmclass_from_dex_by_index(hApkContext context, const char * dex_file, unsigned int idx);

//------------------------------------ Disassembly API

/// @brief Get a method structure given a full dalvik name.
/// @param context APK from where to retrieve the method
/// @param method_name LclassName;->methodName(parameters)RetType
/// @return pointer to a disassembled method
SHURIKENCOREAPI dvmdisassembled_method_t *get_disassembled_method_from_apk(hApkContext context, const char *method_name);

//------------------------------------- Analysis API

/// @brief Obtain one hdvmclassanalysis_t given its hdvmclass_t
/// @param context context from the CORE API
/// @param class_ hdvmclass_t to get its analysis
SHURIKENCOREAPI hdvmclassanalysis_t *get_analyzed_class_by_hdvmclass_from_apk(hApkContext context, hdvmclass_t *class_);

/// @brief Obtain one hdvmclassanalysis_t given its name.
/// @param context APK context from the CORE API
/// @param class_name name of the class to retrieve
SHURIKENCOREAPI hdvmclassanalysis_t *get_analyzed_class_from_apk(hApkContext context, const char *class_name);

/// @brief Obtain one hdvmmethodanalysis_t given its hdvmmethod_t
/// @param context APK context from the CORE API
/// @param method hdvmmethod_t to get its analysis
SHURIKENCOREAPI hdvmmethodanalysis_t *get_analyzed_method_by_hdvmmethod_from_apk(hApkContext context, hdvmmethod_t *method);

/// @brief Obtain one hdvmmethodanalysis_t given its name
/// @param context APK context from the CORE API
/// @param method_full_name dalvik name of the method
SHURIKENCOREAPI hdvmmethodanalysis_t *get_analyzed_method_from_apk(hApkContext context, const char *method_full_name);

};

#endif//SHURIKENLIB_SHURIKEN_PARSERS_CORE_H
