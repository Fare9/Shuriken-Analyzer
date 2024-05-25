//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_disassembler.cpp

#include "shuriken/disassembler/Dex/dex_disassembler.h"
#include "shuriken/common/logger.h"

using namespace shuriken::disassembler::dex;

DexDisassembler::DexDisassembler(parser::dex::Parser * parser)
    : parser(parser) {
    internal_disassembler = std::make_unique<Disassembler>(parser);
    linear_sweep.set_disassembler(internal_disassembler.get());
}

void DexDisassembler::set_disassembly_algorithm(disassembly_algorithm_t algorithm) {
    this->disassembly_algorithm = algorithm;
}

DisassembledMethod* DexDisassembler::get_disassembled_method(std::string method) {
    if (disassembled_methods.find(method) == disassembled_methods.end())
        return nullptr;
    return disassembled_methods[method].get();
}

DisassembledMethod* DexDisassembler::get_disassembled_method(std::string_view method) {
    if (disassembled_methods.find(method) == disassembled_methods.end())
        return nullptr;
    return disassembled_methods[method].get();
}

std::unordered_map<std::string_view,
                   std::unique_ptr<DisassembledMethod>>&
DexDisassembler::get_disassembled_methods() {
  return disassembled_methods;
}

void DexDisassembler::disassembly_dex() {
    auto log = logger();

    log->info("Starting disassembly of the DEX file");

    auto& classes = parser->get_classes();

    for (auto & class_def : classes.get_classdefs()) {
        auto& class_data_item = class_def->get_class_data_item();
        /// first disassemble the direct methods
        for (auto & method : class_data_item.get_direct_methods()) {
            disassemble_encoded_method(method.get());
        }
        /// now the virtual methods
        for (auto & method : class_data_item.get_virtual_methods()) {
            disassemble_encoded_method(method.get());
        }
    }

    log->info("Finished method disassembly");
}

void DexDisassembler::disassemble_encoded_method(shuriken::parser::dex::EncodedMethod* method) {
    auto code_item_struct = method->get_code_item();
    auto buffer_instructions = code_item_struct->get_bytecode();
    std::unique_ptr<DisassembledMethod> disassembled_method;

    auto exceptions_data = internal_disassembler->determine_exception(method);
    auto instructions = linear_sweep.disassembly(code_item_struct->get_bytecode());

    disassembled_methods[method->getMethodID()->dalvik_name_format()] = std::make_unique<DisassembledMethod>(
            method->getMethodID(), code_item_struct->get_registers_size(), exceptions_data, instructions, method->get_flags());
}

std::vector<std::unique_ptr<Instruction>> DexDisassembler::disassembly_buffer(std::span<std::uint8_t> buffer) {
    return linear_sweep.disassembly(buffer);
}