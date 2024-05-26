//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file invalidinstruction_exception.h
// @brief Kind of exception that will keep size of the instruction to
// be disassembled, this will be used by the disassembler to fix the errors

#ifndef SHURIKENLIB_INVALIDINSTRUCTION_EXCEPTION_H
#define SHURIKENLIB_INVALIDINSTRUCTION_EXCEPTION_H

#include <iostream>

namespace exceptions {
    /// @brief Exception raised when one of the instructions has
    /// not a valid format.
    class InvalidInstructionException : public std::exception {
        /// @brief message to show with the exception
        std::string _msg;
        /// @brief Instruction size for disassembler
        std::uint32_t _inst_size;

    public:
        /// @brief Constructor of exception
        /// @param msg message to show to the user
        /// @param inst_Size size of the instruction to skip that size
        InvalidInstructionException(const std::string &msg, std::uint32_t inst_size)
            : _msg(msg), _inst_size(inst_size) {}

        /// @brief Return error message
        /// @return error message in a c string style
        virtual const char *what() const noexcept override {
            return _msg.c_str();
        }

        /// @brief get the size of an incorrectly disassembled instruction
        /// @return size of an instruction
        std::uint32_t size() const {
            return _inst_size;
        }
    };
}// namespace exceptions

#endif//SHURIKENLIB_INVALIDINSTRUCTION_EXCEPTION_H
