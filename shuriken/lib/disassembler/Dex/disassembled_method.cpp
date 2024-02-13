//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file disassembled_method.cpp

#include "shuriken/disassembler/Dex/disassembled_method.h"

using namespace shuriken::disassembler::dex;

DisassembledMethod::DisassembledMethod(std::uint16_t n_of_registers,
                                       exceptions_data_t& exceptions,
                                       instructions_t& instructions) :
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