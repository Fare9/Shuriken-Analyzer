//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file linear_sweep_disassembler.h
// @brief An implementation of a Linear sweep disassembler for Dalvik bytecode.

#ifndef SHURIKENPROJECT_LINEAR_SWEEP_DISASSEMBLER_H
#define SHURIKENPROJECT_LINEAR_SWEEP_DISASSEMBLER_H

#include "shuriken/disassembler/Dex/internal_disassembler.h"

namespace shuriken::disassembler::dex {
    class LinearSweepDisassembler {
    private:
        /// @brief Internal disassembler to decode every instruction
        Disassembler *internal_disassembler;

        /// @brief If there's any switch in code, we will assign to some instructions
        /// the PackedSwitch or the SparswSwitch value
        /// @param instructions all the buffer with the instructions from a method.
        /// @param cache_instructions cache of instructions for avoiding searching
        /// always in the vector
        void assign_switch_if_any(
                std::vector<std::unique_ptr<Instruction>> &instructions,
                std::unordered_map<std::uint64_t, Instruction *> &cache_instructions);

    public:
        LinearSweepDisassembler() = default;

        /// @brief Set the internal disassembler to decode the instructions
        /// @param disassembler disassembler for instruction decoding
        void set_disassembler(Disassembler *disassembler);

        std::vector<std::unique_ptr<Instruction>> disassembly(std::span<std::uint8_t> buffer_bytes);
    };
} // namespace shuriken::disassembler::dex

#endif//SHURIKENPROJECT_LINEAR_SWEEP_DISASSEMBLER_H
