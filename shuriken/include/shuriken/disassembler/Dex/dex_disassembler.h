//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_disassembler.h
// @brief Disassembler offered to the user, this will disassemble each
// method and will return the disassembled methods

#ifndef SHURIKENPROJECT_DEX_DISASSEMBLER_H
#define SHURIKENPROJECT_DEX_DISASSEMBLER_H

#include "shuriken/disassembler/Dex/disassembled_method.h"
#include "shuriken/disassembler/Dex/internal_disassembler.h"
#include "shuriken/disassembler/Dex/linear_sweep_disassembler.h"

#include "shuriken/parser/Dex/parser.h"

#include <unordered_map>

namespace shuriken::disassembler::dex {

    enum class disassembly_algorithm_t {
        LINEAR_SWEEP_DISASSEMBLER
    };

    class DexDisassembler {
    public:
        using disassembled_methods_t = std::unordered_map<std::string_view,
                                                         std::unique_ptr<DisassembledMethod>>;
        using disassembled_methods_s_t = std::unordered_map<std::string_view,
                                                        std::reference_wrapper<const DisassembledMethod>>;

    private:
        /// @brief Disassembly algorithm to use by default linear sweep is used
        disassembly_algorithm_t disassembly_algorithm = disassembly_algorithm_t::LINEAR_SWEEP_DISASSEMBLER;
        /// @brief Internal disassembler to provide to the different algorithms
        std::unique_ptr<Disassembler> internal_disassembler;
        /// @brief Pointer to the parser where information about the structure is stored
        parser::dex::Parser *parser;
        /// @brief Storage for the Disassembled Methods
        disassembled_methods_t
                disassembled_methods;
        disassembled_methods_s_t
                disassembled_methods_s;
        /// @brief Linear sweep disassembler
        LinearSweepDisassembler linear_sweep;

        void disassemble_encoded_method(shuriken::parser::dex::EncodedMethod *method);

    public:
        /// @brief Constructor of the DexDisassembler, this should be called
        /// only if the parsing was correct
        /// @param parser parser for the internal disassembler, this is used
        /// in some of the instructions
        DexDisassembler(parser::dex::Parser *parser);

        /// @brief Set the disassembly algorithm to use in the next calls to
        /// the different disassembly methods.
        /// @param algorithm new algorithm to use
        void set_disassembly_algorithm(disassembly_algorithm_t algorithm);

        /// @brief Obtain a DisassembledMethod object the disassembler keeps
        /// all of them in a map.
        /// @param method class->name_method(description) of the method to retrieve
        /// @return a DisassembledMethod object with the instructions
        DisassembledMethod *get_disassembled_method(std::string method);

        /// @brief Obtain a DisassembledMethod object the disassembler keeps
        /// all of them in a map.
        /// @param method class->name_method(description) of the method to retrieve
        /// @return a DisassembledMethod object with the instructions
        DisassembledMethod *get_disassembled_method(std::string_view method);

        /// @brief Obtain a reference to all the disassembled methods
        /// @return reference to map with all the disassembled methods
        disassembled_methods_s_t &
        get_disassembled_methods();

        disassembled_methods_t &
        get_disassembled_methods_ownership();

        /// @brief This is the most important function from the
        /// disassembler, this function takes the given parser
        /// object and calls one of the internal disassemblers
        /// for retrieving all the instructions from the DEX file
        void disassembly_dex();

        /// @brief Disassembly a buffer of bytes, take the buffer
        /// of bytes as dalvik instructions
        /// @param buffer buffer with possible bytecode for dalvik
        /// @return vector with disassembled instructions
        std::vector<std::unique_ptr<Instruction>>
        disassembly_buffer(std::span<std::uint8_t> buffer);
    };
} // namespace shuriken::disassembler::dex

#endif//SHURIKENPROJECT_DEX_DISASSEMBLER_H
