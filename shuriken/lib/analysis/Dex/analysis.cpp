//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file analysis.cpp

#include "shuriken/analysis/Dex/analysis.h"
#include "shuriken/common/logger.h"

#include <regex>

using namespace shuriken::analysis::dex;

namespace {
  std::vector<std::string_view> split(std::string_view s) {
    std::vector<std::string_view> tokens;
    size_t delimiter_pos = s.find("->");
    if (delimiter_pos != std::string_view::npos) {
      tokens.push_back(s.substr(0, delimiter_pos)); // Class name
      size_t method_start_pos = delimiter_pos + 2;  // Skip the "->"
      size_t open_paren_pos = s.find('(', method_start_pos);
      if (open_paren_pos != std::string_view::npos) {
        tokens.push_back(s.substr(
            method_start_pos, open_paren_pos - method_start_pos)); // Method name
        tokens.push_back(s.substr(open_paren_pos));                // Prototype
      } else {
        // Handle invalid input (no '(' found)
        tokens.push_back(
            s.substr(method_start_pos)); // Method name (if it exists)
        // No prototype found
        tokens.emplace_back("");
      }
    } else {
      // Handle invalid input (no '->' found)
      // Consider the whole input as class name
      tokens.push_back(s);
      // Method name and prototype not found
      tokens.push_back("");
      tokens.push_back("");
    }
    return tokens;
  }
}


Analysis::Analysis(parser::dex::Parser *parser,
                   disassembler::dex::DexDisassembler *disassembler,
                   bool create_xrefs)
    : created_xrefs(!create_xrefs), disassembler(disassembler) {
  if (parser)
    add(parser);
}

void Analysis::add(parser::dex::Parser *parser) {
  auto logger = shuriken::logger();

  parsers.push_back(parser);

  auto &class_dex = parser->get_classes();

  auto it_classes = class_dex.get_classdefs();

  logger->debug("Adding to the analysis {} number of classes",
                std::distance(it_classes.begin(), it_classes.end()));

  auto &all_methods_instructions = disassembler->get_disassembled_methods();

  for (auto &class_def_item : it_classes) {
    auto name = class_def_item->get_class_idx()->get_class_name();
    classes[name] = std::make_unique<ClassAnalysis>(class_def_item.get());
    auto &new_class = classes[name];

    // get the class data item to retrieve the methods
    auto &class_data_item = class_def_item->get_class_data_item();

    logger->debug("Adding to the class {} direct and {} virtual methods",
                  class_data_item.get_number_of_direct_methods(),
                  class_data_item.get_number_of_static_fields());

    // first use the virtual methods
    for (auto &encoded_method : class_data_item.get_virtual_methods()) {
      auto method_id = encoded_method->getMethodID();
      /// now create a method analysis
      auto method_name = method_id->dalvik_name_format();
      methods[method_name] = std::make_unique<MethodAnalysis>(
          encoded_method.get(), all_methods_instructions[method_name].get());
      auto new_method = methods[method_name].get();

      new_class->add_method(new_method);
    }

    // then the direct methods
    for (auto &encoded_method : class_data_item.get_direct_methods()) {
      auto method_id = encoded_method->getMethodID();
      /// now create a method analysis
      auto method_name = method_id->dalvik_name_format();
      methods[method_name] = std::make_unique<MethodAnalysis>(
          encoded_method.get(), all_methods_instructions[method_name].get());
      auto new_method = methods[method_name].get();

      new_class->add_method(new_method);
    }
  }
  logger->info("Analysis: correctly added parser to analysis object");
}

void Analysis::create_xrefs() {
  auto logger = shuriken::logger();

  if (created_xrefs) {
    logger->info("Requested create_xref() method more than once.");
    logger->info(
        "create_xref() will not work again, function will exit right now.");
    logger->info("Please if you want to analyze various dex parsers, add all "
                 "of them first, then call this function.");

    return;
  }

  created_xrefs = true;

  logger->debug("create_xref(): creating xrefs for {} dex files",
                parsers.size());

  for (auto parser : parsers) {
    static size_t i = 0;
    logger->debug("Analyzing {} parser", i++);

    auto &class_dex = parser->get_classes();
    auto it_classes = class_dex.get_classdefs();

    logger->debug("Number of classes to analyze: {}",
                  std::distance(it_classes.begin(), it_classes.end()));

    for (auto &class_def_item : it_classes) {
      static size_t j = 0;
      logger->debug("Analyzing class number {}", j++);

      _create_xrefs(class_def_item.get());
    }
  }
  logger->info("Cross-references correctly created");
}

void Analysis::_create_xrefs(parser::dex::ClassDef *current_class) {

  /// take thename of the analyzed class
  auto current_class_name = current_class->get_class_idx()->get_class_name();
  auto &class_data_item = current_class->get_class_data_item();

  /// get the virtual methods
  auto it_virtual_methods = class_data_item.get_virtual_methods();

  for (auto &virtual_method : it_virtual_methods) {
    _analyze_encoded_method(virtual_method.get(), current_class_name);
  }

  /// get the direc methods
  auto it_direct_methods = class_data_item.get_direct_methods();

  for (auto &direct_method : it_direct_methods) {
    _analyze_encoded_method(direct_method.get(), current_class_name);
  }
}

void Analysis::_analyze_encoded_method(parser::dex::EncodedMethod *method,
                                       std::string_view current_class_name) {
  auto logger = shuriken::logger();

  // Obtain the Method Analysis
  auto current_method_analysis =
      methods[method->getMethodID()->dalvik_name_format()].get();

  auto class_analysis_working_on = classes[current_class_name].get();

  for (auto &instr :
       current_method_analysis->get_disassembled_method()->get_instructions()) {
    auto off = instr->get_address();
    auto instruction = instr.get();
    auto op_value = static_cast<disassembler::dex::DexOpcodes::opcodes>(
        instr->get_instruction_opcode());

    // check for: `const-class` and `new-instance` instructions
    if (op_value == disassembler::dex::DexOpcodes::opcodes::OP_CONST_CLASS ||
        op_value == disassembler::dex::DexOpcodes::opcodes::OP_NEW_INSTANCE) {
      auto const_class_new_instance =
          reinterpret_cast<disassembler::dex::Instruction21c *>(instruction);

      // check we get a TYPE from CONST_CLASS
      // or from NEW_INSTANCE, any other Kind (FIELD, PROTO, etc)
      // it is not valid in this case
      if (const_class_new_instance->get_kind() != shuriken::dex::TYPES::TYPE ||
          std::get<parser::dex::DVMType *>(
              const_class_new_instance->get_source_as_kind())
                  ->get_type() != parser::dex::CLASS)
        return;

      auto dvm_class = reinterpret_cast<parser::dex::DVMClass *>(
          std::get<parser::dex::DVMType *>(
              const_class_new_instance->get_source_as_kind()));
      auto cls_name = dvm_class->get_class_name();

      // avoid analyzing our own class name
      if (cls_name == current_class_name)
        continue;

      // if the name of the class is not already in the classes,
      // probably we are treating with an external class
      if (classes.find(cls_name) == classes.end()) {
        external_classes[cls_name] = std::make_unique<ExternalClass>(cls_name);
        classes[cls_name] =
            std::make_unique<ClassAnalysis>(external_classes[cls_name].get());
      }

      auto oth_cls = classes[cls_name].get();

      /// add the cross references
      class_analysis_working_on->add_xref_to(
          static_cast<shuriken::dex::TYPES::ref_type>(op_value), oth_cls,
          current_method_analysis, off);
      oth_cls->add_xref_from(
          static_cast<shuriken::dex::TYPES::ref_type>(op_value),
          class_analysis_working_on, current_method_analysis, off);

      /// Check if const-class
      if (op_value == disassembler::dex::DexOpcodes::opcodes::OP_CONST_CLASS) {
        current_method_analysis->add_xrefconstclass(oth_cls, off);
        oth_cls->add_xref_const_class(current_method_analysis, off);
      } else {
        current_method_analysis->add_xrefnewinstance(oth_cls, off);
        oth_cls->add_xref_new_instance(current_method_analysis, off);
      }
    }

    /// Check for instructions invoke-*
    else if (disassembler::dex::DexOpcodes::opcodes::OP_INVOKE_VIRTUAL <=
                 op_value &&
             op_value <=
                 disassembler::dex::DexOpcodes::opcodes::OP_INVOKE_INTERFACE) {
      auto invoke_ =
          reinterpret_cast<disassembler::dex::Instruction35c *>(instruction);

      if (invoke_->get_value_kind() != shuriken::dex::TYPES::METH)
        continue;

      auto invoked_method =
          std::get<parser::dex::MethodID *>(invoke_->get_value());

      if (invoked_method->get_class()->get_type() != parser::dex::CLASS) {
        logger->warn("Found a call to a method from non class (type found {})",
                     invoked_method->get_class()->print_type());
        continue;
      }

      /// information of method and class called
      auto oth_method = _resolve_method(invoked_method->dalvik_name_format());
      auto oth_cls = classes[reinterpret_cast<parser::dex::DVMClass *>(
                                 invoked_method->get_class())
                                 ->get_class_name()]
                         .get();

      class_analysis_working_on->add_method_xref_to(current_method_analysis,
                                                    oth_cls, oth_method, off);
      oth_cls->add_method_xref_from(oth_method, class_analysis_working_on,
                                    current_method_analysis, off);

      class_analysis_working_on->add_xref_to(
          static_cast<shuriken::dex::TYPES::ref_type>(op_value), oth_cls,
          oth_method, off);
      oth_cls->add_xref_from(
          static_cast<shuriken::dex::TYPES::ref_type>(op_value),
          class_analysis_working_on, current_method_analysis, off);
    }

    /// Check for instructions like: invoke-xxx/range
    else if (disassembler::dex::DexOpcodes::opcodes::OP_INVOKE_VIRTUAL_RANGE <=
                 op_value &&
             op_value <= disassembler::dex::DexOpcodes::opcodes::
                             OP_INVOKE_INTERFACE_RANGE) {
      auto invoke_xxx_range =
          reinterpret_cast<disassembler::dex::Instruction3rc *>(instruction);

      if (invoke_xxx_range->get_kind() != shuriken::dex::TYPES::METH) {
        continue;
      }

      auto method_id = std::get<parser::dex::MethodID *>(
          invoke_xxx_range->get_index_value());
      /// information of method and class called
      auto oth_method = _resolve_method(method_id->dalvik_name_format());
      auto oth_cls = classes[reinterpret_cast<parser::dex::DVMClass *>(
                                 method_id->get_class())
                                 ->get_class_name()]
                         .get();

      class_analysis_working_on->add_method_xref_to(current_method_analysis,
                                                    oth_cls, oth_method, off);
      oth_cls->add_method_xref_from(oth_method, class_analysis_working_on,
                                    current_method_analysis, off);

      class_analysis_working_on->add_xref_to(
          static_cast<shuriken::dex::TYPES::ref_type>(op_value), oth_cls,
          oth_method, off);
      oth_cls->add_xref_from(
          static_cast<shuriken::dex::TYPES::ref_type>(op_value),
          class_analysis_working_on, current_method_analysis, off);
    }

    /// Now check for string usage
    else if (op_value ==
             disassembler::dex::DexOpcodes::opcodes::OP_CONST_STRING) {
      auto const_string =
          reinterpret_cast<disassembler::dex::Instruction21c *>(instruction);

      if (const_string->get_source_kind() != shuriken::dex::TYPES::STRING)
        continue;

      auto string_value =
          std::get<std::string_view>(const_string->get_source_as_kind());

      if (strings.find(string_value) == strings.end())
        strings[string_value] = std::make_unique<StringAnalysis>(string_value);
      strings[string_value]->add_xreffrom(class_analysis_working_on,
                                          current_method_analysis, off);
    }

    /// check now for field usage, we first
    /// analyze those from OP_IGET to OP_IPUT_SHORT
    /// then those from OP_SGET to OP_SPUT_SHORT
    else if (disassembler::dex::DexOpcodes::opcodes::OP_IGET <= op_value &&
             op_value <=
                 disassembler::dex::DexOpcodes::opcodes::OP_IPUT_SHORT) {
      auto op_i =
          reinterpret_cast<disassembler::dex::Instruction22c *>(instruction);

      if (op_i->get_kind() != shuriken::dex::TYPES::FIELD)
        continue;

      auto checked_field =
          std::get<parser::dex::FieldID *>(op_i->get_checked_id_as_kind());

      auto operation =
          disassembler::dex::InstructionUtils::get_operation_type_from_opcode(
              op_value);

      if (operation == disassembler::dex::DexOpcodes::FIELD_READ_DVM_OPCODE) {
        auto field_item = checked_field->get_encoded_field();

        classes[current_class_name]->add_field_xref_read(
            current_method_analysis, class_analysis_working_on, field_item,
            off);

        // necessary to give a field analysis to the add_xref_read method
        // we can get the created by the add_field_xref_read.
        auto field_analysis =
            classes[current_class_name]->get_field_analysis(field_item);
        current_method_analysis->add_xrefread(class_analysis_working_on,
                                              field_analysis, off);
      } else if (operation ==
                 disassembler::dex::DexOpcodes::FIELD_WRITE_DVM_OPCODE) {
        // retrieve the encoded field from the FieldID
        auto field_item = checked_field->get_encoded_field();

        classes[current_class_name]->add_field_xref_write(
            current_method_analysis, class_analysis_working_on, field_item,
            off);

        // same as before
        auto field_analysis =
            classes[current_class_name]->get_field_analysis(field_item);

        current_method_analysis->add_xrefwrite(class_analysis_working_on,
                                               field_analysis, off);
      }
    }

    else if (disassembler::dex::DexOpcodes::opcodes::OP_SGET <= op_value &&
             op_value <=
                 disassembler::dex::DexOpcodes::opcodes::OP_SPUT_SHORT) {
      auto op_s =
          reinterpret_cast<disassembler::dex::Instruction21c *>(instruction);

      if (op_s->get_kind() != shuriken::dex::TYPES::FIELD)
        continue;

      auto checked_field =
          std::get<parser::dex::FieldID *>(op_s->get_source_as_kind());

      auto operation =
          disassembler::dex::InstructionUtils::get_operation_type_from_opcode(
              op_value);

      if (operation == disassembler::dex::DexOpcodes::FIELD_READ_DVM_OPCODE) {
        auto field_item = checked_field->get_encoded_field();

        classes[current_class_name]->add_field_xref_read(
            current_method_analysis, class_analysis_working_on, field_item,
            off);

        // necessary to give a field analysis to the add_xref_read method
        // we can get the created by the add_field_xref_read.
        auto field_analysis =
            classes[current_class_name]->get_field_analysis(field_item);
        current_method_analysis->add_xrefread(class_analysis_working_on,
                                              field_analysis, off);
      } else if (operation ==
                 disassembler::dex::DexOpcodes::FIELD_WRITE_DVM_OPCODE) {
        // retrieve the encoded field from the FieldID
        auto field_item = checked_field->get_encoded_field();

        classes[current_class_name]->add_field_xref_write(
            current_method_analysis, class_analysis_working_on, field_item,
            off);

        // same as before
        auto field_analysis =
            classes[current_class_name]->get_field_analysis(field_item);

        current_method_analysis->add_xrefwrite(class_analysis_working_on,
                                               field_analysis, off);
      }
    }
  }
}

MethodAnalysis *Analysis::_resolve_method(std::string_view full_name) {

  auto it = methods.find(full_name);

  if (it != methods.end())
    return it->second.get();

  auto tokens = ::split(full_name);
  std::string_view class_name = tokens[0];
  std::string_view method_name = tokens[1];
  std::string_view prototype = tokens[2];

  if (classes.find(class_name) == classes.end()) {
    external_classes[class_name] = std::make_unique<ExternalClass>(class_name);
    // add the external class
    classes[class_name] =
        std::make_unique<ClassAnalysis>(external_classes[class_name].get());
  }

  external_methods[full_name] = std::make_unique<ExternalMethod>(
      class_name, method_name, prototype,
      shuriken::dex::TYPES::access_flags::ACC_PUBLIC);
  auto meth_analysis =
      std::make_unique<MethodAnalysis>(external_methods[full_name].get());
  auto meth_analysis_p_ = meth_analysis.get();
  // add to all the collections we have
  methods[full_name] = std::move(meth_analysis);
  classes[class_name]->add_method(meth_analysis_p_);
  return methods[full_name].get();
}

ClassAnalysis *Analysis::get_class_analysis(std::string_view class_name) {
  if (classes.contains(class_name)) return classes[class_name].get();
  return nullptr;
}

std::unordered_map<std::string_view, std::unique_ptr<ClassAnalysis>> &
Analysis::get_classes() {
  return classes;
}

std::unordered_map<std::string_view , std::unique_ptr<ExternalClass>> &
Analysis::get_external_classes() {
  return external_classes;
}

MethodAnalysis *Analysis::get_method(
    std::variant<parser::dex::EncodedMethod *, ExternalMethod *> method) {
  std::string_view name;
  if (std::holds_alternative<parser::dex::EncodedMethod *>(method)) {
    auto m = std::get<parser::dex::EncodedMethod *>(method);
    name = m->getMethodID()->dalvik_name_format();
  } else {
    auto m = std::get<ExternalMethod*>(method);
    name = m->pretty_method_name();
  }

  if (methods.contains(name)) return methods[name].get();
  return nullptr;
}

MethodAnalysis *Analysis::get_method_analysis_by_name(std::string_view dalvik_name) {
  if (methods.contains(dalvik_name)) return methods[dalvik_name].get();
  return nullptr;
}

shuriken::parser::dex::MethodID *Analysis::get_method_id_by_name(std::string_view dalvik_name) {
  if (methods.contains(dalvik_name)) return methods[dalvik_name]->get_encoded_method()->getMethodID();
  return nullptr;
}

std::unordered_map<std::string_view, std::unique_ptr<MethodAnalysis>> &
Analysis::get_methods() {
  return methods;
}

std::unordered_map<std::string_view, std::unique_ptr<ExternalMethod>> &
Analysis::get_external_methods() {
  return external_methods;
}

FieldAnalysis *Analysis::get_field_analysis(parser::dex::EncodedField *field) {
  auto f_it = std::ranges::find_if(all_fields, [&](FieldAnalysis * field_analysis) -> bool {
    field_analysis->get_encoded_field()->get_field()->pretty_field() == field->get_field()->pretty_field();
  });

  if (f_it == all_fields.end()) return nullptr;
  return *f_it;
}

std::vector<FieldAnalysis *> &Analysis::get_fields() {
  return all_fields;
}

std::unordered_map<std::string_view, std::unique_ptr<StringAnalysis>> &
Analysis::get_string_analysis() {
  return strings;
}

std::vector<ClassAnalysis *> Analysis::find_classes(const std::string& name, bool no_external) {
  std::vector<ClassAnalysis*> cls_analyses;

  std::vector<ClassAnalysis *> found_classes;
  std::regex const class_name_regex(name);

  for (const auto &c : classes) {
    if (no_external && c.second->is_class_external())
      continue;
    if (std::regex_search(c.second->name().data(), class_name_regex))
      found_classes.push_back(c.second.get());
  }

  return found_classes;
}

std::vector<MethodAnalysis *> Analysis::find_methods(const std::string& class_name,
                                           const std::string& method_name,
                                           const std::string& descriptor,
                                           const std::string& accessflags,
                                           bool no_external) {
  std::vector<MethodAnalysis *> methods_vector;

  std::regex class_name_regex(class_name),
      method_name_regex(method_name),
      descriptor_regex(descriptor),
      accessflags_regex(accessflags);

  for (const auto &m : methods) {
    const auto &method = m.second;

    if (no_external && method->external())
      continue;

    auto access_flags = shuriken::dex::Utils::get_types_as_string(method->get_access_flags());

    if (std::regex_search(method->get_class_name().data(), class_name_regex) &&
        std::regex_search(method->get_name().data(), method_name_regex) &&
        std::regex_search(access_flags, accessflags_regex))
      methods_vector.push_back(method.get());
  }

  return methods_vector;
}

std::vector<StringAnalysis *> Analysis::find_strings(const std::string &str) {
  std::vector<StringAnalysis *> strings_list;
  std::regex const str_reg(str);

  for (const auto &s : strings)
  {
    if (std::regex_search(s.first.data(), str_reg))
      strings_list.push_back(s.second.get());
  }

  return strings_list;
}

std::vector<FieldAnalysis *> Analysis::find_fields(const std::string& class_name,
                                         const std::string& field_name,
                                         const std::string& field_type,
                                         const std::string& accessflags) {
  std::regex class_name_regex(class_name),
      field_name_regex(field_name),
      field_type_regex(field_type),
      accessflags_regex(accessflags);

  std::vector<FieldAnalysis *> fields_list;

  for (const auto &c : classes) {
    if (!std::regex_search(c.second->name().data(), class_name_regex))
      continue;

    for (const auto &f : c.second->get_fields()) {
      std::string access_flags_str = shuriken::dex::Utils::get_types_as_string(f.second->get_encoded_field()->get_flags());

      if (std::regex_search(f.second->get_name().data(), field_name_regex) &&
          std::regex_search(f.second->get_encoded_field()->get_field()->field_type()->get_raw_type().data(),field_type_regex) &&
          std::regex_search(access_flags_str, accessflags_regex))
        fields_list.push_back(f.second.get());
    }
  }

  return fields_list;
}