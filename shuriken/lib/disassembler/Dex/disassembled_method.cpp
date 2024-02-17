//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file disassembled_method.cpp

#include "shuriken/disassembler/Dex/disassembled_method.h"
#include <sstream>
#include <iomanip>

using namespace shuriken::disassembler::dex;

DisassembledMethod::DisassembledMethod(shuriken::parser::dex::MethodID* method_id,
                                       std::uint16_t n_of_registers,
                                       exceptions_data_t& exceptions,
                                       instructions_t& instructions) :
                                       method_id(method_id),
                                       n_of_registers(n_of_registers),
                                       exception_information(std::move(exceptions)),
                                       instructions(std::move(instructions)) {
    instructions_raw.reserve(this->instructions.size());
    for (const auto & instr : instructions) {
        instructions_raw.emplace_back(instr.get());
    }
}

std::uint16_t DisassembledMethod::get_number_of_registers() const {
    return n_of_registers;
}

size_t DisassembledMethod::get_number_of_exceptions() const {
    return exception_information.size();
}

size_t DisassembledMethod::get_number_of_instructions() const {
    return instructions.size();
}

it_exceptions_data DisassembledMethod::get_exceptions() {
    return make_range(exception_information.begin(), exception_information.end());
}

it_instructions DisassembledMethod::get_instructions() {
    return make_range(instructions.begin(), instructions.end());
}

std::span<Instruction*> DisassembledMethod::get_ref_to_instructions(size_t init, size_t end) {
    if (end > instructions_raw.size())
        throw std::runtime_error{"Error, last index out of bounds"};
    if (init >= end)
        throw std::runtime_error{"Error, init must be lower to end"};
    std::span<Instruction*> block{instructions_raw.begin()+init, instructions_raw.end()+end};
    return block;
}

std::string_view DisassembledMethod::print_method() {
    if (method_string.empty()) {
        std::stringstream output;
        output << method_id->dalvik_name_format() + "\n";
        output << "\t.registers " << std::to_string(n_of_registers) << "\n";
        int id = 0;
        for (auto & instr : instructions) {
            /// check the information for showing exception
            for (const auto & exception : exception_information) {
                if (id == exception.try_value_start_addr)
                    output << ".try:\n";
                for (const auto & catch_data : exception.handler) {
                    if (id == catch_data.handler_start_addr)
                        output << ".catch:\n";
                }
            }

            output << std::hex << std::setw(8) << std::setfill('0') << id << '\t';
            /// now print the instruction
            instr->print_instruction(output);
            id += instr->get_instruction_length();
            output << '\n';
        }
        output << ".end method";
        method_string = output.str();
    }
    return method_string;
}