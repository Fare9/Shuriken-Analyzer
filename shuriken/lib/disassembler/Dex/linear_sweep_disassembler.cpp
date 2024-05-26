//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file linear_sweep_disassembler.cpp

#include "shuriken/disassembler/Dex/linear_sweep_disassembler.h"
#include "shuriken/common/logger.h"
#include "shuriken/exceptions/invalidinstruction_exception.h"
#include <memory>

using namespace shuriken::disassembler::dex;

void LinearSweepDisassembler::set_disassembler(Disassembler *disassembler) {
    this->internal_disassembler = disassembler;
}

std::vector<std::unique_ptr<Instruction>> LinearSweepDisassembler::disassembly(std::span<std::uint8_t> buffer_bytes) {
    auto log = logger();
    std::unordered_map<std::uint64_t, Instruction *> cache_instr;
    std::uint64_t idx = 0;                                 // index of the instr
    std::vector<std::unique_ptr<Instruction>> instructions;// all the instructions from the method
    std::unique_ptr<Instruction> instr;                    // insruction to create
    auto buffer_size = buffer_bytes.size();                // size of the buffer
    DexOpcodes::opcodes opcode;                            // opcode of the operation
    bool exist_switch = false;                             // check a switch exist

    while (idx < buffer_size) {
        opcode = static_cast<DexOpcodes::opcodes>(buffer_bytes[idx]);

        try {
            if (!exist_switch &&
                (opcode == DexOpcodes::opcodes::OP_PACKED_SWITCH ||
                 opcode == DexOpcodes::opcodes::OP_SPARSE_SWITCH))
                exist_switch = true;

            instr = internal_disassembler->disassemble_instruction(
                    static_cast<std::uint32_t>(opcode),
                    buffer_bytes,
                    idx);

            if (instr) {
                instr->set_address(idx);
                instructions.push_back(std::move(instr));
                cache_instr[idx] = instructions.back().get();
                idx += instructions.back()->get_instruction_length();
            }
        } catch (const exceptions::InvalidInstructionException &i) {
            log->error("InvalidInstructionException in the index: {}, opcode: {}, message: {}, instr size: {}",
                       idx, static_cast<std::uint32_t>(opcode), i.what(), i.size());
            // in case there was an invalid instr
            // create a DalvikIncorrectInstruction
            instr = std::make_unique<DalvikIncorrectInstruction>(buffer_bytes, idx, i.size());
            instr->set_address(idx);
            // set the instr into the vector
            instructions.push_back(std::move(instr));
            cache_instr[idx] = instructions.back().get();
            idx += i.size();
        } catch (const std::exception &e) {
            log->error("Error reading index: {}, opcode: {}, message: {}",
                       idx, static_cast<std::uint32_t>(opcode), e.what());
            idx += 1;
        }
    }

    if (exist_switch)
        assign_switch_if_any(instructions, cache_instr);

    std::sort(instructions.begin(),
              instructions.end(),
              [=](const std::unique_ptr<Instruction> &a, const std::unique_ptr<Instruction> &b) { return a->get_address() < b->get_address(); });

    return instructions;
}

void LinearSweepDisassembler::assign_switch_if_any(
        std::vector<std::unique_ptr<Instruction>> &instructions,
        std::unordered_map<std::uint64_t, Instruction *> &cache_instructions) {
    for (auto &instr: instructions) {
        auto op_code = static_cast<DexOpcodes::opcodes>(instr->get_instruction_opcode());

        if (op_code == DexOpcodes::opcodes::OP_PACKED_SWITCH ||
            op_code == DexOpcodes::opcodes::OP_SPARSE_SWITCH) {
            auto instr31t = reinterpret_cast<Instruction31t *>(instr.get());

            auto switch_idx = instr31t->get_address() + (instr31t->get_offset() * 2);

            auto it = cache_instructions.find(switch_idx);

            if (it != cache_instructions.end()) {
                if (op_code == DexOpcodes::opcodes::OP_PACKED_SWITCH)
                    instr31t->set_packed_switch(reinterpret_cast<PackedSwitch *>(it->second));
                else// DexOpcodes::opcodes::OP_SPARSE_SWITCH
                    instr31t->set_sparse_switch(reinterpret_cast<SparseSwitch *>(it->second));
            }
        }
    }
}