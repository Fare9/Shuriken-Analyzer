//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file analysis.h
// @brief This file offer all the analysis functionality in just one class
// we will use all the utilities from analysis.hpp

#ifndef SHURIKENPROJECT_ANALYSIS_H
#define SHURIKENPROJECT_ANALYSIS_H

#include "shuriken/analysis/Dex/dex_analysis.h"
#include "shuriken/disassembler/Dex/dex_disassembler.h"

namespace shuriken::analysis::dex {

    using namespace shuriken::disassembler::dex;

    class Analysis {
    public:
        using class_analyses_t = std::unordered_map<std::string, std::unique_ptr<ClassAnalysis>>;
        using class_analyses_s_t = std::unordered_map<std::string, std::reference_wrapper<const ClassAnalysis>>;

        using external_classes_t = std::unordered_map<std::string, std::unique_ptr<ExternalClass>>;
        using external_classes_s_t = std::unordered_map<std::string, std::reference_wrapper<const ExternalClass>>;

        using method_analyses_t = std::unordered_map<std::string, std::unique_ptr<MethodAnalysis>>;
        using method_analyses_s_t = std::unordered_map<std::string, std::reference_wrapper<const MethodAnalysis>>;

        using external_methods_t = std::unordered_map<std::string, std::unique_ptr<ExternalMethod>>;
        using external_methods_s_t = std::unordered_map<std::string, std::reference_wrapper<const ExternalMethod>>;

        using string_analyses_t = std::unordered_map<std::string, std::unique_ptr<StringAnalysis>>;
        using string_analyses_s_t = std::unordered_map<std::string, std::reference_wrapper<const StringAnalysis>>;


    private:
        /// @brief all the dex parsers from the analysis
        std::vector<parser::dex::Parser *> parsers;

        /// @brief list of class analysis by classes' names
        class_analyses_t class_analyses;
        class_analyses_s_t class_analyses_s;

        /// @brief list of external classes by classes' names
        external_classes_t external_classes;
        external_classes_s_t external_classes_s;

        /// @brief analysis of strings by the string value
        string_analyses_t string_analyses;
        string_analyses_s_t string_analyses_s;

        /// @brief analysis of methods by the dalvik name of the method
        method_analyses_t method_analyses;
        method_analyses_s_t method_analyses_s;

        /// @brief external methods by dalvik name of the method
        external_methods_t external_methods;
        external_methods_s_t external_methods_s;

        std::vector<FieldAnalysis *> field_analyses;

        disassembler::dex::DexDisassembler *disassembler;

        /// @brief are the xrefs already created?
        bool created_xrefs = false;

        /// @brief Internal method for creating the xref for `current_class`
        /// There are four steps involved in getting the xrefs:
        ///     * xrefs for class instantiation and static class usage.
        ///     * xrefs for method calls
        ///     * xrefs for string usage
        ///     * xrefs field manipuation
        /// All the information is stored in the Analysis objects.
        /// It might be quite slow as all instructions are parsed.
        /// @param current_class class to create the xrefs.
        void _create_xrefs(parser::dex::ClassDef &current_class);

        /// @brief Helper function to analyze the xrefs from an encoded method
        void _analyze_encoded_method(parser::dex::EncodedMethod *method, std::string &current_class_name);

        /// @brief Helper function to get a ClassAnalysis, or in case it doesn't exist
        /// create it as an external class
        ClassAnalysis *_get_class_or_create_external(std::string class_name);

        /// @brief Get a method by its hash, return the MethodAnalysis object
        /// in case it doesn't exists, create an ExternalMethod
        /// @param dalvik_format full method name
        /// @return a MethodAnalysis pointer
        MethodAnalysis *_resolve_method(std::string full_name);

    public:
        Analysis(parser::dex::Parser *parser,
                 disassembler::dex::DexDisassembler *disassembler, bool create_xrefs);

        /// @brief Add all the classes and methods from a parser
        /// to the analysis class.
        /// @param parser parser to extract the information
        void add(parser::dex::Parser *parser);

    private:
        /// @brief Helper function to add every ClassDef from a Parser object.
        void _add_classdef(parser::dex::ClassDef &class_def_item,
                           DexDisassembler::disassembled_methods_t
                                   &all_methods_instructions);

        /// @brief Helper function to add an EncodedMethod from a ClassDef.
        void _add_encoded_method(parser::dex::EncodedMethod *encoded_method,
                                 ClassAnalysis *new_class,
                                 DexDisassembler::disassembled_methods_t
                                         &all_methods_instructions);

    public:
        /// @brief Create class, method, string and field cross references
        /// if you are using multiple DEX files, this function must
        /// be called when all DEX files are added.
        /// If you call the function after every DEX file, it will only
        /// work for the first time.
        /// ADD ALL DEX FIRST
        void create_xrefs();

        /// @brief Get a ClassAnalysis object by the class name
        /// @param class_name name of the class to retrieve
        /// @return pointer to ClassAnalysis*
        ClassAnalysis *get_class_analysis(std::string class_name);

        /// @brief Get a reference to the classes
        /// @return reference to map with classes
        class_analyses_s_t &
        get_classes();

        /// @brief Get a reference to external classes
        /// @return reference to external classes
        external_classes_s_t &
        get_external_classes();

        /// @brief Get a MethodAnalysis pointer given an Encoded or External Method
        /// @param method method to retrieve
        /// @return MethodAnalysis from the given method
        MethodAnalysis *get_method(
                std::variant<parser::dex::EncodedMethod *, ExternalMethod *> method);

        /// @brief Obtain a method anaylsis by different values
        /// @param class_name class name of the method
        /// @param method_name name of the method
        /// @param method_descriptor prototype descriptor of the method
        /// @return pointer to MethodAnalysis or nullptr
        MethodAnalysis *get_method_analysis_by_name(std::string dalvik_name);

        /// @brief Obtain a MethodID by different values
        /// @param class_name class name of the method
        /// @param method_name name of the method
        /// @param method_descriptor prototype descriptor of the method
        /// @return pointer to MethodID or nullptr
        parser::dex::MethodID *get_method_id_by_name(std::string dalvik_name);

        /// @brief Return a reference to the method analysis
        /// @return reference to map woth MethodAnalysis
        method_analyses_s_t &
        get_methods();

        /// @brief Return a reference to the ExternalMethods
        /// @return reference to map with ExternalMethod
        external_methods_s_t &
        get_external_methods();

        /// @brief Get a field given an encoded field
        /// @param field field to obtain the FieldAnalysis
        /// @return FieldAnalysis object
        FieldAnalysis *get_field_analysis(parser::dex::EncodedField *field);

        /// @brief Get all the fields from all the classes
        /// @return reference to vector with all the fields
        std::vector<FieldAnalysis *> &get_fields();

        /// @brief Get a reference to the StringAnalysis map
        /// @return reference to StringAnalysis map
        string_analyses_s_t &
        get_string_analysis();

        /// @brief Find classes by name with regular expression,
        /// the method returns a list of ClassAnalysis object that
        /// match the regex.
        /// @param name regex of name class to find
        /// @param no_external want external classes too?
        /// @return vector with all ClassAnalysis objects
        std::vector<ClassAnalysis *> find_classes(const std::string &name, bool no_external);

        /// @brief Find MethodAnalysis object by name with regular expression.
        /// This time is necessary to specify more values for the method.
        /// @param class_name name of the class to retrieve
        /// @param method_name name of the method to retrieve
        /// @param descriptor descriptor of this method
        /// @param accessflags
        /// @param no_external
        /// @return
        std::vector<MethodAnalysis *> find_methods(const std::string &class_name,
                                                   const std::string &method_name,
                                                   const std::string &descriptor,
                                                   const std::string &accessflags,
                                                   bool no_external);

        /// @brief Find the strings that match a provided regular expression
        /// @param str regular expression to find as string
        /// @return vector of StringAnalysis objects
        std::vector<StringAnalysis *> find_strings(const std::string &str);

        /// @brief Find FieldAnalysis objects using regular expressions
        /// find those that are in classes.
        /// @param class_name name of the class where field is
        /// @param field_name name of the field
        /// @param field_type type of the field
        /// @param accessflags access flags of the field
        /// @return vector with all the fields that match the regex
        std::vector<FieldAnalysis *> find_fields(const std::string &class_name,
                                                 const std::string &field_name,
                                                 const std::string &field_type,
                                                 const std::string &accessflags);
    };

}// namespace shuriken::analysis::dex


#endif// SHURIKENPROJECT_ANALYSIS_H
