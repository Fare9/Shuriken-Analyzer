//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file disassembler.h
// @brief Disassembler engine for Shuriken, instructions
// are disassembled one by one, information from the parser
// is needed.

#ifndef SHURIKENPROJECT_INTERNAL_DISASSEMBLER_H
#define SHURIKENPROJECT_INTERNAL_DISASSEMBLER_H

#include "shuriken/disassembler/Dex/dex_instructions.h"
#include "shuriken/disassembler/Dex/disassembled_method.h"
#include "shuriken/parser/Dex/parser.h"

namespace shuriken {
    namespace disassembler {
        namespace dex {
            class Disassembler {
            private:
                /// @brief pointer to the parser of the DEX file
                parser::dex::Parser *parser;
                /// @brief pointer to the last instruction generated
                /// by the Disassembler
                Instruction *last_instr;
                /// @brief In case there are no handlers, create a throwable one
                parser::dex::DVMClass throwable_class{"Ljava/lang/Throwable;"};

            public:
                Disassembler(parser::dex::Parser *parser);

                Disassembler() = default;

                ~Disassembler() = default;

                /// @brief Get an instruction object from the op
                /// @param opcode op code of the instruction to return
                /// @param bytecode reference to the bytecode for disassembly
                /// @param index index of the current instruction to analyze
                /// @return unique pointer to the disassembled Instruction
                std::unique_ptr<Instruction> disassemble_instruction(
                        std::uint32_t opcode,
                        std::span<uint8_t> bytecode,
                        std::size_t index);

                /// @brief Determine given the last instruction the next instruction
                /// to run, the bytecode is retrieved from a :class:EncodedMethod.
                /// The offsets are calculated in number of bytes from the start of the
                /// method. Note, the offsets inside the bytecode are denoted in 16 bits
                /// units but method returns actual byte offsets.
                /// @param instruction instruction to obtain the next instructions
                /// @param curr_idx Current idx to calculate the newer one
                /// @return list of different offsets where code can go after the current
                /// instruction. Instructions like `if` or `switch` have more than one
                /// target, but `throw`, `return` and `goto` have just one. If entered
                /// opcode is not a branch instruction, next instruction is returned.
                std::vector<std::int64_t> determine_next(Instruction *instruction,
                                                         std::uint64_t curr_idx);

                /// @brief Same as the other `determine_next` but the instruction we give
                /// is the instruction `last_instr` that Disassembler stores.
                /// @param curr_idx Current idx to calculate the newer one
                /// @return list of different offsets where code can go after the current
                /// instruction. Instructions like `if` or `switch` have more than one
                /// target, but `throw`, `return` and `goto` have just one. If entered
                /// opcode is not a branch instruction, next instruction is returned.
                std::vector<std::int64_t> determine_next(std::uint64_t curr_idx);

                /// @brief Given an instruction check if it is a conditional jump
                /// and retrieve in that case the target of the jump
                /// @param instr instruction to retrieve the target of the jump
                /// @return target of a conditional jump
                std::int16_t get_conditional_jump_target(Instruction *instr);

                /// @brief Given an instruction check if it is an unconditional jump
                /// and retrieve in that case the target of the jump
                /// @param instr instruction to retrieve the target of the jump
                /// @return target of an unconditional jump
                std::int32_t get_unconditional_jump_target(Instruction *instr);

                /// @brief Retrieve information from possible exception code inside
                /// of a method
                /// @param method method to extract exception data
                /// @return exception data in a vector
                std::vector<exception_data_t> determine_exception(parser::dex::EncodedMethod *method);
            };
        }// namespace dex
    }    // namespace disassembler
}// namespace shuriken

#endif//SHURIKENPROJECT_INTERNAL_DISASSEMBLER_H
