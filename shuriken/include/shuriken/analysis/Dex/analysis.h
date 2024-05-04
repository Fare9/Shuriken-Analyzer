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

class Analysis {
private:
  /// @brief all the dex parsers from the analysis
  std::vector<parser::dex::Parser *> parsers;

  /// @brief list of class analysis by classes' names
  std::unordered_map<std::string_view, std::unique_ptr<ClassAnalysis>> classes;

  /// @brief list of external classes by classes' names
  std::unordered_map<std::string_view, std::unique_ptr<ExternalClass>>
      external_classes;

  /// @brief analysis of strings by the string value
  std::unordered_map<std::string_view, std::unique_ptr<StringAnalysis>> strings;

  /// @brief analysis of methods by the dalvik name of the method
  std::unordered_map<std::string_view, std::unique_ptr<MethodAnalysis>> methods;

  /// @brief external methods by dalvik name of the method
  std::unordered_map<std::string_view, std::unique_ptr<ExternalMethod>>
      external_methods;

  std::vector<FieldAnalysis *> all_fields;

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
  void _create_xrefs(parser::dex::ClassDef *current_class);
  void _analyze_encoded_method(parser::dex::EncodedMethod* method, std::string_view current_class_name);

  /// @brief Get a method by its hash, return the MethodAnalysis object
  /// in case it doesn't exists, create an ExternalMethod
  /// @param dalvik_format full method name
  /// @return a MethodAnalysis pointer
  MethodAnalysis *_resolve_method(std::string_view full_name);

public:
  Analysis(parser::dex::Parser *parser,
           disassembler::dex::DexDisassembler *disassembler, bool create_xrefs);

  /// @brief Add all the classes and methods from a parser
  /// to the analysis class.
  /// @param parser parser to extract the information
  void add(parser::dex::Parser *parser);

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
  ClassAnalysis *get_class_analysis(std::string_view class_name);

  /// @brief Get a reference to the classes
  /// @return reference to map with classes
  std::unordered_map<std::string_view, std::unique_ptr<ClassAnalysis>> &
  get_classes();

  /// @brief Get a reference to external classes
  /// @return reference to external classes
  std::unordered_map<std::string_view , std::unique_ptr<ExternalClass>> &
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
  MethodAnalysis *get_method_analysis_by_name(std::string_view dalvik_name);

  /// @brief Obtain a MethodID by different values
  /// @param class_name class name of the method
  /// @param method_name name of the method
  /// @param method_descriptor prototype descriptor of the method
  /// @return pointer to MethodID or nullptr
  parser::dex::MethodID *get_method_id_by_name(std::string_view dalvik_name);

  /// @brief Return a reference to the method analysis
  /// @return reference to map woth MethodAnalysis
  std::unordered_map<std::string_view, std::unique_ptr<MethodAnalysis>> &
  get_methods();

  /// @brief Return a reference to the ExternalMethods
  /// @return reference to map with ExternalMethod
  std::unordered_map<std::string_view, std::unique_ptr<ExternalMethod>> &
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
  std::unordered_map<std::string_view, std::unique_ptr<StringAnalysis>> &
  get_string_analysis();

  /// @brief Find classes by name with regular expression,
  /// the method returns a list of ClassAnalysis object that
  /// match the regex.
  /// @param name regex of name class to find
  /// @param no_external want external classes too?
  /// @return vector with all ClassAnalysis objects
  std::vector<ClassAnalysis *> find_classes(const std::string& name, bool no_external);

  /// @brief Find MethodAnalysis object by name with regular expression.
  /// This time is necessary to specify more values for the method.
  /// @param class_name name of the class to retrieve
  /// @param method_name name of the method to retrieve
  /// @param descriptor descriptor of this method
  /// @param accessflags
  /// @param no_external
  /// @return
  std::vector<MethodAnalysis *> find_methods(const std::string& class_name,
                                             const std::string& method_name,
                                             const std::string& descriptor,
                                             const std::string& accessflags,
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
  std::vector<FieldAnalysis *> find_fields(const std::string& class_name,
                                           const std::string& field_name,
                                           const std::string& field_type,
                                           const std::string& accessflags);
};

} // namespace shuriken::analysis::dex


#endif // SHURIKENPROJECT_ANALYSIS_H
