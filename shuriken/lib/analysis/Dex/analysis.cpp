//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file analysis.cpp

#include "shuriken/analysis/Dex/analysis.h"
#include "shuriken/common/logger.h"

#include <regex>

using namespace shuriken::analysis::dex;
using namespace shuriken::disassembler::dex;

namespace {
    /// Given a full name, return a vector of std::string_view with the
    /// class name, the method name, and the prototype of the method
    std::vector<std::string_view> split(std::string_view s) {
        std::vector<std::string_view> tokens;
        size_t delimiter_pos = s.find("->");
        if (delimiter_pos != std::string_view::npos) {
            tokens.push_back(s.substr(0, delimiter_pos));// Class name
            size_t method_start_pos = delimiter_pos + 2; // Skip the "->"
            size_t open_paren_pos = s.find('(', method_start_pos);
            if (open_paren_pos != std::string_view::npos) {
                tokens.push_back(s.substr(
                        method_start_pos, open_paren_pos - method_start_pos));// Method name
                tokens.push_back(s.substr(open_paren_pos));                   // Prototype
            } else {
                // Handle invalid input (no '(' found)
                tokens.push_back(
                        s.substr(method_start_pos));// Method name (if it exists)
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
}// namespace

Analysis::Analysis(parser::dex::Parser *parser,
                   disassembler::dex::DexDisassembler *disassembler,
                   bool create_xrefs)
    : created_xrefs(!create_xrefs), disassembler(disassembler) {
    if (parser)
        add(parser);
}


void Analysis::add(parser::dex::Parser *parser) {
    auto logger = shuriken::logger();

    /// For adding more DEX files to the analysis classes
    /// what we do is to retrieve the parser to get all the
    /// information from the DEX file and add it to the list
    /// of analysis. Retrieve the instructions from the
    /// disassembler. Finally, retrieve the class def items
    /// that will be used later for creating the class analysis.

    parsers.push_back(parser);

    auto &class_dex = parser->get_classes();

    auto it_classes = class_dex.get_classdefs();

    logger->debug("Adding to the analysis {} number of classes",
                  std::distance(it_classes.begin(), it_classes.end()));

    auto &all_methods_instructions = disassembler->get_disassembled_methods_ownership();

    for (auto &class_def_item: it_classes) {
        _add_classdef(class_def_item, all_methods_instructions);
    }
    logger->info("Analysis: correctly added parser to analysis object");
}

void Analysis::_add_classdef(
        parser::dex::ClassDef &class_def_item,
        DexDisassembler::disassembled_methods_t
                &all_methods_instructions) {
    auto logger = shuriken::logger();

    // Create a class analysis, we will work with the created object
    auto name = std::string(class_def_item.get_class_idx()->get_class_name());
    class_analyses.insert({name, std::make_unique<ClassAnalysis>(&class_def_item)});
    auto &new_class = class_analyses[name];

    // get the class data item to retrieve the methods
    auto &class_data_item = class_def_item.get_class_data_item();

    logger->debug("Adding to the class {} direct and {} virtual methods",
                  class_data_item.get_number_of_direct_methods(),
                  class_data_item.get_number_of_static_fields());

    // first use the virtual methods
    for (auto &encoded_method: class_data_item.get_virtual_methods()) {
        _add_encoded_method(&encoded_method, new_class.get(),
                            all_methods_instructions);
    }

    // then the direct methods
    for (auto &encoded_method: class_data_item.get_direct_methods()) {
        _add_encoded_method(&encoded_method, new_class.get(),
                            all_methods_instructions);
    }
}

void Analysis::_add_encoded_method(
        parser::dex::EncodedMethod *encoded_method, ClassAnalysis *new_class,
        DexDisassembler::disassembled_methods_t
                &all_methods_instructions) {
    auto method_id = encoded_method->getMethodID();
    /// now create a method analysis
    auto method_name = std::string(method_id->dalvik_name_format());
    auto &disassembled = all_methods_instructions[method_name];
    method_analyses.insert({method_name, std::make_unique<MethodAnalysis>(encoded_method, disassembled.get())});
    auto new_method = method_analyses[method_name].get();

    new_class->add_method(new_method);
}

ExternalField *Analysis::get_external_field(shuriken::parser::dex::FieldID *field) {
    auto full_name = std::string(field->pretty_field());
    if (external_fields.contains(full_name))
        return external_fields[full_name].get();
    external_fields.insert({full_name,
                            std::make_unique<ExternalField>(
                                    field->field_class()->get_raw_type(),
                                    field->field_name(),
                                    field->field_type()->print_type())});
    auto &external_field = external_fields[full_name];
    return external_field.get();
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

    for (auto parser: parsers) {
        static size_t i = 0;
        logger->debug("Analyzing {} parser", i++);

        auto &class_dex = parser->get_classes();
        auto it_classes = class_dex.get_classdefs();

        logger->debug("Number of classes to analyze: {}",
                      std::distance(it_classes.begin(), it_classes.end()));

        for (auto &class_def_item: it_classes) {
            static size_t j = 0;
            logger->debug("Analyzing class number {}", j++);

            _create_xrefs(class_def_item);
        }
    }
    logger->info("Cross-references correctly created");
}

void Analysis::_create_xrefs(parser::dex::ClassDef &current_class) {

    /// take the name of the analyzed class
    auto current_class_name = std::string(current_class.get_class_idx()->get_class_name());
    auto &class_data_item = current_class.get_class_data_item();

    /// get the virtual methods
    auto it_virtual_methods = class_data_item.get_virtual_methods();

    for (auto &virtual_method: it_virtual_methods) {
        _analyze_encoded_method(&virtual_method, current_class_name);
    }

    /// get the direct methods
    auto it_direct_methods = class_data_item.get_direct_methods();

    for (auto &direct_method: it_direct_methods) {
        _analyze_encoded_method(&direct_method, current_class_name);
    }
}

void Analysis::_analyze_encoded_method(parser::dex::EncodedMethod *method,
                                       std::string &current_class_name) {
    auto logger = shuriken::logger();

    // Obtain the Method Analysis
    auto current_method_analysis =
            method_analyses[std::string(method->getMethodID()->dalvik_name_format())].get();

    auto class_analysis_working_on = class_analyses[current_class_name].get();

    for (auto instr:
         current_method_analysis->get_disassembled_method()->get_instructions()) {
        auto off = instr->get_address();
        auto instruction = instr;
        auto op_value =
                static_cast<DexOpcodes::opcodes>(instr->get_instruction_opcode());

        // check for: `const-class` and `new-instance` instructions
        if (op_value == DexOpcodes::opcodes::OP_CONST_CLASS ||
            op_value == DexOpcodes::opcodes::OP_NEW_INSTANCE) {
            auto const_class_new_instance =
                    reinterpret_cast<disassembler::dex::Instruction21c *>(instruction);
            auto source_dvmtype = std::get<parser::dex::DVMType *>(
                    const_class_new_instance->get_source_as_kind());

            // check we get a TYPE from CONST_CLASS
            // or from NEW_INSTANCE, any other Kind (FIELD, PROTO, etc)
            // it is not valid in this case
            if (const_class_new_instance->get_kind() != shuriken::dex::TYPES::TYPE ||
                source_dvmtype->get_type() != parser::dex::CLASS)
                return;

            auto dvm_class = reinterpret_cast<parser::dex::DVMClass *>(
                    std::get<parser::dex::DVMType *>(
                            const_class_new_instance->get_source_as_kind()));
            auto cls_name = std::string(dvm_class->get_class_name());

            // avoid analyzing our own class name
            if (cls_name == current_class_name)
                continue;

            auto oth_cls = _get_class_or_create_external(cls_name);

            if (oth_cls == nullptr)
                continue;

            /// add the cross references
            class_analysis_working_on->add_xref_to(
                    static_cast<shuriken::dex::TYPES::ref_type>(op_value), oth_cls,
                    current_method_analysis, off);
            oth_cls->add_xref_from(
                    static_cast<shuriken::dex::TYPES::ref_type>(op_value),
                    class_analysis_working_on, current_method_analysis, off);

            /// Check if const-class
            if (op_value == DexOpcodes::opcodes::OP_CONST_CLASS) {
                current_method_analysis->add_xrefconstclass(oth_cls, off);
                oth_cls->add_xref_const_class(current_method_analysis, off);
            } else {
                current_method_analysis->add_xrefnewinstance(oth_cls, off);
                oth_cls->add_xref_new_instance(current_method_analysis, off);
            }
        }

        /// Check for instructions invoke-*
        else if (DexOpcodes::opcodes::OP_INVOKE_VIRTUAL <= op_value &&
                 op_value <= DexOpcodes::opcodes::OP_INVOKE_INTERFACE) {
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
            auto oth_method = _resolve_method(std::string(invoked_method->dalvik_name_format()));
            auto cls_name =
                    std::string(reinterpret_cast<parser::dex::DVMClass *>(invoked_method->get_class())
                                        ->get_class_name());
            auto oth_cls = _get_class_or_create_external(cls_name);

            if (oth_cls == nullptr)
                continue;// an external class?

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
        else if (DexOpcodes::opcodes::OP_INVOKE_VIRTUAL_RANGE <= op_value &&
                 op_value <= DexOpcodes::opcodes::OP_INVOKE_INTERFACE_RANGE) {
            auto invoke_xxx_range =
                    reinterpret_cast<disassembler::dex::Instruction3rc *>(instruction);

            if (invoke_xxx_range->get_kind() != shuriken::dex::TYPES::METH) {
                continue;
            }

            auto method_id = std::get<parser::dex::MethodID *>(
                    invoke_xxx_range->get_index_value());
            /// information of method and class called
            auto oth_method = _resolve_method(std::string(method_id->dalvik_name_format()));
            auto cls_name =
                    reinterpret_cast<parser::dex::DVMClass *>(method_id->get_class())
                            ->get_class_name();
            auto oth_cls = _get_class_or_create_external(std::string(cls_name));

            if (oth_cls == nullptr)
                continue;

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
        else if (op_value == DexOpcodes::opcodes::OP_CONST_STRING) {
            auto const_string =
                    reinterpret_cast<disassembler::dex::Instruction21c *>(instruction);

            if (const_string->get_source_kind() != shuriken::dex::TYPES::STRING)
                continue;

            auto string_value =
                    std::string(std::get<std::string_view>(const_string->get_source_as_kind()));

            if (string_analyses.find(string_value) == string_analyses.end())
                string_analyses.insert({string_value, std::make_unique<StringAnalysis>(string_value)});
            string_analyses[string_value]->add_xreffrom(class_analysis_working_on,
                                                        current_method_analysis, off);
        }

        /// check now for field usage, we first
        /// analyze those from OP_IGET to OP_IPUT_SHORT
        /// then those from OP_SGET to OP_SPUT_SHORT
        else if (DexOpcodes::opcodes::OP_IGET <= op_value &&
                 op_value <= DexOpcodes::opcodes::OP_IPUT_SHORT) {
            auto op_i =
                    reinterpret_cast<disassembler::dex::Instruction22c *>(instruction);

            if (op_i->get_kind() != shuriken::dex::TYPES::FIELD)
                continue;

            auto checked_field =
                    std::get<parser::dex::FieldID *>(op_i->get_checked_id_as_kind());

            auto operation =
                    disassembler::dex::InstructionUtils::get_operation_type_from_opcode(
                            op_value);

            if (operation == DexOpcodes::FIELD_READ_DVM_OPCODE) {
                auto field_item = checked_field->get_encoded_field();
                FieldAnalysis *field_analysis = nullptr;

                if (field_item != nullptr) {
                    class_analyses[current_class_name]->add_field_xref_read(
                            current_method_analysis, class_analysis_working_on, field_item,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(field_item);
                } else {
                    auto external_field = get_external_field(checked_field);
                    class_analyses[current_class_name]->add_field_xref_read(
                            current_method_analysis, class_analysis_working_on, external_field,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(external_field);
                }

                current_method_analysis->add_xrefread(class_analysis_working_on,
                                                      field_analysis, off);


            } else if (operation == DexOpcodes::FIELD_WRITE_DVM_OPCODE) {
                // retrieve the encoded field from the FieldID
                auto field_item = checked_field->get_encoded_field();
                FieldAnalysis *field_analysis = nullptr;

                if (field_item != nullptr) {
                    class_analyses[current_class_name]->add_field_xref_write(
                            current_method_analysis, class_analysis_working_on, field_item,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(field_item);
                } else {
                    auto external_field = get_external_field(checked_field);
                    class_analyses[current_class_name]->add_field_xref_write(
                            current_method_analysis, class_analysis_working_on, external_field,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(external_field);
                }
                current_method_analysis->add_xrefwrite(class_analysis_working_on,
                                                       field_analysis, off);
            }
        }

        else if (DexOpcodes::opcodes::OP_SGET <= op_value &&
                 op_value <= DexOpcodes::opcodes::OP_SPUT_SHORT) {
            auto op_s =
                    reinterpret_cast<disassembler::dex::Instruction21c *>(instruction);

            if (op_s->get_kind() != shuriken::dex::TYPES::FIELD)
                continue;

            auto checked_field =
                    std::get<parser::dex::FieldID *>(op_s->get_source_as_kind());

            auto operation =
                    disassembler::dex::InstructionUtils::get_operation_type_from_opcode(
                            op_value);

            if (operation == DexOpcodes::FIELD_READ_DVM_OPCODE) {
                auto field_item = checked_field->get_encoded_field();
                FieldAnalysis *field_analysis = nullptr;
                if (field_item != nullptr) {
                    class_analyses[current_class_name]->add_field_xref_read(
                            current_method_analysis, class_analysis_working_on, field_item,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(field_item);
                } else {
                    auto external_field = get_external_field(checked_field);
                    class_analyses[current_class_name]->add_field_xref_read(
                            current_method_analysis, class_analysis_working_on, external_field,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(external_field);
                }
                current_method_analysis->add_xrefread(class_analysis_working_on,
                                                      field_analysis, off);
            } else if (operation == DexOpcodes::FIELD_WRITE_DVM_OPCODE) {
                // retrieve the encoded field from the FieldID
                auto field_item = checked_field->get_encoded_field();
                FieldAnalysis *field_analysis = nullptr;

                if (field_item != nullptr) {
                    class_analyses[current_class_name]->add_field_xref_write(
                            current_method_analysis, class_analysis_working_on, field_item,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(field_item);
                } else {
                    auto external_field = get_external_field(checked_field);
                    class_analyses[current_class_name]->add_field_xref_write(
                            current_method_analysis, class_analysis_working_on, external_field,
                            off);
                    field_analysis =
                            class_analyses[current_class_name]->get_field_analysis(external_field);
                }

                current_method_analysis->add_xrefwrite(class_analysis_working_on,
                                                       field_analysis, off);
            }
        }
    }
}

ClassAnalysis *
Analysis::_get_class_or_create_external(std::string class_name) {
    ClassAnalysis *cls = nullptr;
    // if the name of the class is not already in the classes,
    // probably we are retrieving an external class
    if (class_analyses.find(class_name) == class_analyses.end()) {
        external_classes.insert({class_name, std::make_unique<ExternalClass>(class_name)});
        class_analyses.insert({class_name, std::make_unique<ClassAnalysis>(external_classes[class_name].get())});
    }
    cls = class_analyses[class_name].get();
    return cls;
}

MethodAnalysis *Analysis::_resolve_method(std::string full_name) {

    auto it = method_analyses.find(full_name);

    if (it != method_analyses.end())
        return it->second.get();

    auto tokens = ::split(full_name);
    std::string_view class_name = tokens[0];
    std::string_view method_name = tokens[1];
    std::string_view prototype = tokens[2];

    std::string className(class_name.substr(1, class_name.size() - 2));
    // Replace '/' with '.'
    for (char &c: className) {
        if (c == '/') {
            c = '.';
        }
    }
    class_name = className;

    auto classAnalysis = _get_class_or_create_external(className);

    external_methods.insert({full_name, std::make_unique<ExternalMethod>(
                                                class_name, method_name, prototype,
                                                shuriken::dex::TYPES::access_flags::ACC_PUBLIC)});
    auto meth_analysis =
            std::make_unique<MethodAnalysis>(external_methods[full_name].get());
    // add to all the collections we have
    method_analyses.insert({full_name, std::move(meth_analysis)});
    classAnalysis->add_method(method_analyses[full_name].get());
    return method_analyses[full_name].get();
}

ClassAnalysis *Analysis::get_class_analysis(std::string class_name) {
    if (class_analyses.contains(class_name))
        return class_analyses[class_name].get();
    return nullptr;
}

Analysis::class_analyses_s_t &
Analysis::get_classes() {
    if (class_analyses_s.empty() || class_analyses_s.size() != class_analyses.size()) {
        class_analyses_s.clear();
        for (const auto &entry: class_analyses)
            class_analyses_s.insert({entry.first, std::ref(*entry.second)});
    }
    return class_analyses_s;
}

Analysis::external_classes_s_t &
Analysis::get_external_classes() {
    if (external_classes_s.empty() || external_classes_s.size() != external_classes.size()) {
        for (const auto &entry: external_classes)
            external_classes_s.insert({entry.first, std::ref(*entry.second)});
    }
    return external_classes_s;
}

MethodAnalysis *Analysis::get_method(
        std::variant<parser::dex::EncodedMethod *, ExternalMethod *> method) {
    std::string name;
    if (std::holds_alternative<parser::dex::EncodedMethod *>(method)) {
        auto m = std::get<parser::dex::EncodedMethod *>(method);
        name = m->getMethodID()->dalvik_name_format();
    } else {
        auto m = std::get<ExternalMethod *>(method);
        name = m->pretty_method_name();
    }

    if (method_analyses.contains(name))
        return method_analyses[name].get();
    return nullptr;
}

MethodAnalysis *
Analysis::get_method_analysis_by_name(std::string dalvik_name) {
    if (method_analyses.contains(dalvik_name))
        return method_analyses[dalvik_name].get();
    return nullptr;
}

shuriken::parser::dex::MethodID *
Analysis::get_method_id_by_name(std::string dalvik_name) {
    if (method_analyses.contains(dalvik_name))
        return method_analyses[dalvik_name]->get_encoded_method()->getMethodID();
    return nullptr;
}

Analysis::method_analyses_s_t &
Analysis::get_methods() {
    if (method_analyses_s.empty() || method_analyses.size() != method_analyses_s.size()) {
        for (const auto &entry: method_analyses) {
            method_analyses_s.insert({entry.first, std::ref(*entry.second)});
        }
    }
    return method_analyses_s;
}

Analysis::external_methods_s_t &
Analysis::get_external_methods() {
    if (external_methods_s.empty() || external_methods_s.size() != external_methods.size()) {
        for (const auto &entry: external_methods)
            external_methods_s.insert({entry.first, std::ref(*entry.second)});
    }
    return external_methods_s;
}

Analysis::external_fields_s_t &
Analysis::get_external_fields() {
    if (external_fields_s.empty() || external_fields_s.size() != external_fields.size()) {
        for (const auto &entry: external_fields)
            external_fields_s.insert({entry.first, std::ref(*entry.second)});
    }
    return external_fields_s;
}

FieldAnalysis *Analysis::get_field_analysis(parser::dex::EncodedField *field) {
    if (field_analyses.empty())
        get_fields();

    auto f_it = std::ranges::find_if(
            field_analyses, [&](FieldAnalysis *field_analysis) -> bool {
                if (field_analysis->is_external()) {
                    return field_analysis->get_external_field()->pretty_field_name()
                           == field->get_field()->pretty_field();
                }
                else {
                    return field_analysis->get_encoded_field()
                                   ->get_field()
                                   ->pretty_field() == field->get_field()->pretty_field();
                }
            });

    if (f_it == field_analyses.end())
        return nullptr;
    return *f_it;
}

std::vector<FieldAnalysis *> &Analysis::get_fields() {
    if (!field_analyses.empty())
        return field_analyses;

    for (const auto &c: class_analyses) {
        for (const auto &f: c.second->get_fields())
            field_analyses.push_back(f.second.get());
    }

    return field_analyses;
}

Analysis::string_analyses_s_t &
Analysis::get_string_analysis() {
    if (string_analyses_s.empty() || string_analyses_s.size() != string_analyses.size()) {
        for (const auto &entry: string_analyses)
            string_analyses_s.insert({entry.first, std::ref(*entry.second)});
    }
    return string_analyses_s;
}

std::vector<ClassAnalysis *> Analysis::find_classes(const std::string &name,
                                                    bool no_external) {
    std::vector<ClassAnalysis *> cls_analyses;

    std::vector<ClassAnalysis *> found_classes;
    std::regex const class_name_regex(name);

    for (const auto &c: class_analyses) {
        if (no_external && c.second->is_class_external())
            continue;
        if (std::regex_search(c.second->name().data(), class_name_regex))
            found_classes.push_back(c.second.get());
    }

    return found_classes;
}

std::vector<MethodAnalysis *>
Analysis::find_methods(const std::string &class_name,
                       const std::string &method_name,
                       const std::string &descriptor,
                       const std::string &accessflags, bool no_external) {
    std::vector<MethodAnalysis *> methods_vector;

    std::regex class_name_regex(class_name), method_name_regex(method_name),
            descriptor_regex(descriptor), accessflags_regex(accessflags);

    for (const auto &m: method_analyses) {
        const auto &method = m.second;

        if (no_external && method->external())
            continue;

        auto access_flags =
                shuriken::dex::Utils::get_types_as_string(method->get_access_flags());

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

    for (const auto &s: string_analyses) {
        if (std::regex_search(s.first.data(), str_reg))
            strings_list.push_back(s.second.get());
    }

    return strings_list;
}

std::vector<FieldAnalysis *> Analysis::find_fields(
        const std::string &class_name, const std::string &field_name,
        const std::string &field_type, const std::string &accessflags) {
    std::regex class_name_regex(class_name), field_name_regex(field_name),
            field_type_regex(field_type), accessflags_regex(accessflags);

    std::vector<FieldAnalysis *> fields_list;

    for (const auto &c: class_analyses) {
        if (!std::regex_search(c.second->name().data(), class_name_regex))
            continue;

        for (const auto &f: c.second->get_fields()) {
            std::string access_flags_str = shuriken::dex::Utils::get_types_as_string(
                    f.second->get_encoded_field()->get_flags());

            if (std::regex_search(f.second->get_name().data(), field_name_regex) &&
                std::regex_search(f.second->get_encoded_field()
                                          ->get_field()
                                          ->field_type()
                                          ->get_raw_type()
                                          .data(),
                                  field_type_regex) &&
                std::regex_search(access_flags_str, accessflags_regex))
                fields_list.push_back(f.second.get());
        }
    }

    return fields_list;
}