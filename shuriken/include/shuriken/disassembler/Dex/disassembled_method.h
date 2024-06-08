//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file disassembled_method.h
// @brief Object to keep all the information from the disassembled method

#ifndef SHURIKENPROJECT_DISASSEMBLED_METHOD_H
#define SHURIKENPROJECT_DISASSEMBLED_METHOD_H

#include "shuriken/disassembler/Dex/dex_instructions.h"
#include "shuriken/parser/Dex/dex_types.h"

#include <vector>

namespace shuriken {
    namespace disassembler {
        namespace dex {
            /// @brief Information for the handler
            /// of exceptions, handler type, the
            /// start address of it and basic blocks
            typedef struct _handler_data {
                parser::dex::DVMType *handler_type;
                std::uint64_t handler_start_addr;
            } handler_data_t;

            /// @brief Information for the exceptions in the
            /// code
            typedef struct _exception_data {
                std::uint64_t try_value_start_addr;
                std::uint64_t try_value_end_addr;
                std::vector<handler_data_t> handler;
            } exception_data_t;

            using instructions_t = std::vector<std::unique_ptr<
                    Instruction>>;
            using it_instructions = iterator_range<instructions_t::iterator>;

            using exceptions_data_t = std::vector<exception_data_t>;
            using it_exceptions_data = iterator_range<exceptions_data_t::iterator>;

            /// @brief For storing information about a disassembled
            /// method we will keep that information in a class, this
            /// class will keep the number of registers from the disassembled
            /// method, the information about the handlers and
            /// the instructions
            class DisassembledMethod {
            private:
                /// @brief MethodID with the name of the method
                shuriken::parser::dex::MethodID *method_id;
                /// @brief Number of registers from the method
                std::uint16_t n_of_registers;
                /// @brief vector with all the exception information
                /// for the method
                exceptions_data_t exception_information;
                /// @brief store the instructions from the method
                instructions_t instructions;
                /// @brief store raw pointers to return reference to the instructions
                std::vector<Instruction *> instructions_raw;
                /// @brief representation of the method in string format
                std::string method_string;
                /// @brief Access flags from the instruction for the representation
                shuriken::dex::TYPES::access_flags access_flags;

            public:
                /// @brief Constructor of disassembled method.
                /// @param n_of_registers number of registers used in the method
                /// @param exceptions structure of the exceptions
                /// @param instructions vector of instructions of the method
                DisassembledMethod(shuriken::parser::dex::MethodID *method_id,
                                   std::uint16_t n_of_registers,
                                   exceptions_data_t &exceptions,
                                   instructions_t &instructions,
                                   shuriken::dex::TYPES::access_flags access_flags);

                ~DisassembledMethod() = default;

                shuriken::parser::dex::MethodID *get_method_id();

                /// @brief Get the number of registers
                /// @return number of registers
                std::uint16_t get_number_of_registers() const;

                /// @brief Get the number of exceptions available in the method
                /// @return number of exceptions
                size_t get_number_of_exceptions() const;

                /// @brief Get the number of available instructions in the method
                /// @return number of instructions
                size_t get_number_of_instructions() const;

                /// @brief Get the iterator to the exceptions from the method
                /// @return iterator of the exceptions
                it_exceptions_data get_exceptions();

                /// @brief Get the iterator to the instructions from the method
                /// @return iterator of the instructions
                it_instructions get_instructions();

                /// @return const container to the instructions
                const std::vector<Instruction *> &get_instructions_container();

                /// @brief Get a constant access to a part of the instructions from the method
                /// @param init first index from the instructions
                /// @param end last index from the instructions
                /// @return constant reference to instructions
                std::span<Instruction *> get_ref_to_instructions(size_t init, size_t end);

                /// @brief Get a disassembled representation of the method in string format
                /// @param print_address print the address from each instruction
                /// @return disassembled method string
                std::string_view print_method(bool print_address = true);
            };
        }// namespace dex
    }    // namespace disassembler
}// namespace shuriken

#endif//SHURIKENPROJECT_DISASSEMBLED_METHOD_H
