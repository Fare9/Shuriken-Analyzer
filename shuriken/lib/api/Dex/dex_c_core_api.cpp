//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_core_api.cpp
// @brief Implements the necessary functions for the DEX part of
// the core api to work

#include "shuriken/api/C/shuriken_core.h"
#include "shuriken/parser/shuriken_parsers.h"
#include "shuriken/disassembler/Dex/disassembled_method.h"
#include "shuriken/disassembler/Dex/dex_disassembler.h"

#include <unordered_map>

namespace {

    const int TAG = 'SKEN';

    typedef struct {
        /// @brief tag to check that the provided structure is correct
        int tag;
        /// @brief DEX parser from shuriken
        shuriken::parser::dex::Parser * parser;
        /// @brief number of classes
        std::uint16_t number_of_classes;
        /// @brief classes created from DEX information
        hdvmclass_t * classes;
        /// @brief all the methods from the DEX (to access all the methods)
        std::unordered_map<std::string_view, hdvmmethod_t*> methods;

        /// @brief DEX disassembler from shuriken
        shuriken::disassembler::dex::DexDisassembler * disassembler;
        /// @brief Lazy disassembled methods
        std::unordered_map<std::string_view, dvmdisassembled_method_t *> disassembled_methods;
    } dex_opaque_struct_t;

    /// @brief Add the data to an instruction from the core API, from an instruction from shuriken library
    /// @param instruction instruction from shuriken library.
    /// @param core_instruction instruction from the core API.
    void fill_dex_instruction(shuriken::disassembler::dex::Instruction * instruction,
                              hdvminstruction_t * core_instruction) {
        core_instruction->instruction_type = static_cast<dexinsttype_e>(instruction->get_instruction_type());
        core_instruction->instruction_length = instruction->get_instruction_length();
        core_instruction->address = instruction->get_address();
        core_instruction->op = instruction->get_instruction_opcode();
        core_instruction->disassembly = instruction->print_instruction().data();
    }

    /// @brief Add the exception information from an exception data of shuriken library, to one from the core C API
    /// @param exception_data exception information from shuriken library.
    /// @param core_exception_data exception information from core API.
    void fill_dex_exception_information(shuriken::disassembler::dex::exception_data_t * exception_data,
                                        dvmexceptions_data_t * core_exception_data) {
        core_exception_data->try_value_start_addr = exception_data->try_value_start_addr;
        core_exception_data->try_value_end_addr = exception_data->try_value_end_addr;
        core_exception_data->n_of_handlers = exception_data->handler.size();
        if (core_exception_data->n_of_handlers > 0) {
            core_exception_data->handler =
                    (dvmhandler_data_t*) malloc(core_exception_data->n_of_handlers * sizeof(dvmhandler_data_t));
            for (size_t i = 0; i < core_exception_data->n_of_handlers; i++) {
                core_exception_data->handler->handler_start_addr = exception_data->handler[i].handler_start_addr;
                core_exception_data->handler->handler_type = exception_data->handler[i].handler_type->get_raw_type().data();
            }
        }
    }

    /// @brief Create a full method from a DisassembledMethod from the shuriken library.
    /// @param opaque_struct opaque structure where the information is stored
    /// @param disassembled_method method to create in the core C API
    /// @param method_core_api method from the core api to fill
    void fill_dex_disassembled_method(
                                dex_opaque_struct_t  * opaque_struct,
                                shuriken::disassembler::dex::DisassembledMethod * disassembled_method,
                                dvmdisassembled_method_t * method_core_api) {
        size_t i = 0;
        method_core_api->method_id =
                get_method_by_name(opaque_struct,
                                   disassembled_method->get_method_id()->dalvik_name_format().data());
        method_core_api->n_of_registers = disassembled_method->get_number_of_registers();
        method_core_api->n_of_instructions = disassembled_method->get_number_of_instructions();
        method_core_api->n_of_exceptions = disassembled_method->get_number_of_exceptions();
        method_core_api->method_string = disassembled_method->print_method(true).data();

        // initialize the instructions
        method_core_api->instructions =
                (hdvminstruction_t*) malloc(method_core_api->n_of_instructions*(sizeof(hdvminstruction_t)));

        i = 0;
        for (const auto & instruction : disassembled_method->get_instructions()) {
            fill_dex_instruction(instruction.get(), &method_core_api->instructions[i++]);
        }

        // initialize the exception information
        method_core_api->exception_information =
                (dvmexceptions_data_t *) malloc(method_core_api->n_of_exceptions * (sizeof(dvmexceptions_data_t)));

        i = 0;
        for (auto & exception_data : disassembled_method->get_exceptions()) {
            fill_dex_exception_information(&exception_data, &method_core_api->exception_information[i++]);
        }
    }

    /// @brief Correctly free the memory from a disassembled method
    /// @param method_core_api method to destroy
    void destroy_disassembled_method(dvmdisassembled_method_t * method_core_api) {
        if (method_core_api->n_of_instructions > 0 && method_core_api->instructions != nullptr)
            free(method_core_api->instructions);
        if (method_core_api->n_of_exceptions > 0 && method_core_api->exception_information != nullptr) {
            if (method_core_api->exception_information->n_of_handlers > 0
                    && method_core_api->exception_information->handler != nullptr) {
                free(method_core_api->exception_information->handler);
                method_core_api->exception_information->handler = nullptr;
            }
            free(method_core_api->exception_information);
            method_core_api->exception_information = nullptr;
        }
    }

    /// @brief From an EncodedMethod fills the data of a method structure
    /// @param encoded_method method from the internal library
    /// @param method structure for the C core API to fill data
    void fill_dex_method(shuriken::parser::dex::EncodedMethod * encoded_method, hdvmmethod_t * method) {
        const auto method_id = encoded_method -> getMethodID();

        method -> method_name = method_id -> get_method_name().data();
        method -> prototype = method_id -> get_prototype() -> get_dalvik_prototype().data();
        method -> access_flags = encoded_method -> get_flags();
        method -> code_size = encoded_method -> get_code_item() -> get_bytecode().size();
        method -> code = encoded_method -> get_code_item() -> get_bytecode().data();
        method -> dalvik_name = encoded_method -> getMethodID() -> dalvik_name_format().data();
        method -> demangled_name = encoded_method -> getMethodID() -> demangle().data();
    }

    /// @brief From an EncodedField fills the data of a field structure
    /// @param encoded_field field from the internal library
    /// @param field structure for the C core API to fill data
    void fill_dex_field(shuriken::parser::dex::EncodedField * encoded_field, hdvmfield_t * field) {
        auto field_id = encoded_field -> get_field();
        auto field_type = field_id->field_type();

        field -> name = field_id -> field_name().data();
        field -> access_flags = encoded_field -> get_flags();
        field -> type_value = field_id -> field_type() -> get_raw_type().data();
        field -> fundamental_value = FUNDAMENTAL_NONE;

        auto type = field_type -> get_type();

        if (type == shuriken::parser::dex::FUNDAMENTAL) {
            field -> type = FUNDAMENTAL;
            auto fundamental = dynamic_cast < shuriken::parser::dex::DVMFundamental * > (field_type);
            field -> fundamental_value = static_cast < hfundamental_e > (fundamental -> get_fundamental_type());
        } else if (type == shuriken::parser::dex::CLASS) {
            field->type = CLASS;
        } else if (type == shuriken::parser::dex::ARRAY) {
            field -> type = ARRAY;
            auto array = reinterpret_cast < shuriken::parser::dex::DVMArray * > (field_type);
            if (array -> get_array_base_type() -> get_type() == shuriken::parser::dex::FUNDAMENTAL) {
                const auto fundamental = reinterpret_cast <
                        const shuriken::parser::dex::DVMFundamental * > (array -> get_array_base_type());
                field -> fundamental_value = static_cast < hfundamental_e > (fundamental -> get_fundamental_type());
            }
        } else {
            throw std::runtime_error("Error, not supported type...");
        }
    }

    /// @brief Fill an opaque structure with the parsed data
    /// @param parser DEX parser with the data to include in the structure
    /// @param opaque_struct structure that we will fill with parser data
    void fill_dex_opaque_struct(shuriken::parser::dex::Parser * parser, dex_opaque_struct_t * opaque_struct) {
        if (parser == nullptr || opaque_struct == nullptr)
            return;
        opaque_struct -> tag = TAG;
        opaque_struct -> parser = parser;
        opaque_struct -> number_of_classes = parser -> get_header().get_dex_header_const().class_defs_size;
        opaque_struct -> classes = (hdvmclass_t * ) malloc(opaque_struct -> number_of_classes * sizeof(hdvmclass_t));
        size_t i = 0;

        auto & classes = parser -> get_classes();

        for (auto & class_def: classes.get_classdefs()) {
            auto class_idx = class_def -> get_class_idx();
            auto super_class = class_def -> get_superclass();
            auto & class_data_item = class_def -> get_class_data_item();
            auto new_class = & opaque_struct -> classes[i++];

            new_class -> class_name = class_idx -> get_class_name().data();
            if (super_class)
                new_class -> super_class = super_class -> get_class_name().data();
            if (!class_def -> get_source_file().empty())
                new_class -> source_file = class_def -> get_source_file().data();
            new_class -> access_flags = class_def -> get_access_flags();
            new_class -> direct_methods_size = class_data_item.get_number_of_direct_methods();
            new_class -> virtual_methods_size = class_data_item.get_number_of_virtual_methods();
            new_class -> instance_fields_size = class_data_item.get_number_of_instance_fields();
            new_class -> static_fields_size = class_data_item.get_number_of_static_fields();

            /// fill the methods
            new_class -> virtual_methods = (hdvmmethod_t * ) malloc(new_class -> virtual_methods_size * sizeof(hdvmmethod_t));
            for (size_t j = 0; j < new_class -> virtual_methods_size; j++) {
                fill_dex_method(class_data_item.get_virtual_method_by_id(j), &new_class->virtual_methods[j]);
                opaque_struct->methods[class_data_item.get_virtual_method_by_id(j)->getMethodID()->dalvik_name_format()]
                    = &new_class->virtual_methods[j];
            }
            new_class -> direct_methods = (hdvmmethod_t * ) malloc(new_class -> direct_methods_size * sizeof(hdvmmethod_t));
            for (size_t j = 0; j < new_class -> direct_methods_size; j++) {
                fill_dex_method(class_data_item.get_direct_method_by_id(j), &new_class->direct_methods[j]);
                opaque_struct->methods[class_data_item.get_direct_method_by_id(j)->getMethodID()->dalvik_name_format()]
                        = &new_class->direct_methods[j];
            }
            /// fill the fields
            new_class -> instance_fields = (hdvmfield_t * ) malloc(new_class -> instance_fields_size * sizeof(hdvmfield_t));
            for (size_t j = 0; j < new_class -> instance_fields_size; j++)
                fill_dex_field(class_data_item.get_instance_field_by_id(j), & new_class -> instance_fields[j]);
            new_class -> static_fields = (hdvmfield_t * ) malloc(new_class -> static_fields_size * sizeof(hdvmfield_t));
            for (size_t j = 0; j < new_class -> static_fields_size; j++)
                fill_dex_field(class_data_item.get_static_field_by_id(j), & new_class -> static_fields[j]);
        }

    }

    /// @brief Correctly free the memory from a hdvmclass_t
    /// @param class_ class to release its memory
    void destroy_class_data(hdvmclass_t * class_) {
        if (class_ -> direct_methods) {
            free(class_ -> direct_methods);
            class_ -> direct_methods = nullptr;
        }
        if (class_ -> virtual_methods) {
            free(class_ -> virtual_methods);
            class_ -> virtual_methods = nullptr;
        }
        if (class_ -> static_fields) {
            free(class_ -> static_fields);
            class_ -> static_fields = nullptr;
        }
        if (class_ -> instance_fields) {
            free(class_ -> instance_fields);
            class_ -> instance_fields = nullptr;
        }
    }

    /// @brief Destroy the whole opaque struct
    /// @param dex_opaque_struct opaque structure from dex to destroy
    void destroy_opaque_struct(dex_opaque_struct_t * dex_opaque_struct) {
        if (dex_opaque_struct -> classes) {
            destroy_class_data(dex_opaque_struct -> classes);
            free(dex_opaque_struct -> classes);
            dex_opaque_struct -> classes = nullptr;
        }

        if (dex_opaque_struct -> parser) {
            delete dex_opaque_struct -> parser;
            dex_opaque_struct -> parser = nullptr;
        }

        if (dex_opaque_struct -> disassembler) {
            for (auto & method : dex_opaque_struct->disassembled_methods) {
                destroy_disassembled_method(method.second);
                method.second = nullptr;
            }
            dex_opaque_struct->disassembled_methods.clear();
            delete dex_opaque_struct -> disassembler;
            dex_opaque_struct -> disassembler = nullptr;
        }
    }

}

hDexContext parse_dex(const char * filePath) {
    auto * opaque_struct = new dex_opaque_struct_t();
    shuriken::parser::dex::Parser * parser;

    try {
        parser = shuriken::parser::parse_dex(filePath);
    } catch (std::runtime_error & ) {
        return nullptr;
    }
    opaque_struct -> parser = parser;
    fill_dex_opaque_struct(parser, opaque_struct);

    return reinterpret_cast < hDexContext > (opaque_struct);
}

void destroy_dex(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return;
    destroy_opaque_struct(opaque_struct);
}

size_t get_number_of_strings(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return 0;
    auto * p = opaque_struct->parser;
    auto & strings = p -> get_strings();
    return strings.get_number_of_strings();
}

const char * get_string_by_id(hDexContext context, size_t i) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return nullptr;
    auto * p = opaque_struct->parser;
    auto & strings = p -> get_strings();
    if (i >= strings.get_number_of_strings()) return nullptr;
    return reinterpret_cast <
            const char * > (strings.get_string_by_id(i).data());
}

uint16_t get_number_of_classes(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return 0;
    return opaque_struct->number_of_classes;
}

hdvmclass_t * get_class_by_id(hDexContext context, uint16_t i) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG || i >= opaque_struct->number_of_classes) return nullptr;
    return &opaque_struct->classes[i];
}

hdvmclass_t * get_class_by_name(hDexContext context, const char *class_name) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) return nullptr;
    for (size_t i = 0; i < opaque_struct->number_of_classes; i++) {
        if (!strcmp(opaque_struct->classes[i].class_name, class_name))
            return &opaque_struct->classes[i];
    }
    return nullptr;
}

hdvmmethod_t * get_method_by_name(hDexContext context, const char *method_name) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    std::string_view m_name{method_name};
    if (!opaque_struct || opaque_struct -> tag != TAG || opaque_struct->methods.contains(m_name)) return nullptr;
    return opaque_struct->methods.at(m_name);
}

void disassemble_dex(hDexContext context) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG) throw std::runtime_error{"Error, provided DEX context is incorrect"};
    opaque_struct->disassembler = new shuriken::disassembler::dex::DexDisassembler(opaque_struct->parser);
    opaque_struct->disassembler->disassembly_dex();
}

dvmdisassembled_method_t *get_disassembled_method(hDexContext context, const char *method_name) {
    auto * opaque_struct = reinterpret_cast < dex_opaque_struct_t * > (context);
    if (!opaque_struct || opaque_struct -> tag != TAG || opaque_struct->disassembler == nullptr) return nullptr;
    auto m_name = std::string_view{method_name};
    // if it was previously created
    if (opaque_struct->disassembled_methods.contains(m_name)) return opaque_struct->disassembled_methods.at(m_name);
    // if not create it
    auto disassembled_method = opaque_struct->disassembler->get_disassembled_method(m_name);
    auto * method = (dvmdisassembled_method_t*) malloc (sizeof (dvmdisassembled_method_t));
    fill_dex_disassembled_method(opaque_struct, disassembled_method, method);
    // add it to the cache
    opaque_struct->disassembled_methods[disassembled_method->get_method_id()->dalvik_name_format()] = method;
    /// return it
    return method;
}