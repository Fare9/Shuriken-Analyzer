//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file disassembler.cpp

#include "shuriken/disassembler/Dex/internal_disassembler.h"
#include "shuriken/common/logger.h"

using namespace shuriken::disassembler::dex;

namespace {
    /// @brief definition of a generator function for
    /// generating the different instructions
    typedef std::unique_ptr<Instruction> (*generator_func)(std::span<uint8_t>, std::size_t, shuriken::parser::dex::Parser *);

    /// @brief Template that will generate all the instructions
    /// getter user in the disassembler
    /// @tparam T Instruction to generate with this function
    /// @param bytecode bytecode to parse in the instruction
    /// @param index index in the bytecode
    /// @param parser parser for some of the instructions
    /// @return unique pointer with a new instruction
    template<class T>
    std::unique_ptr<Instruction>
    get_instruction(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser) {
        return std::make_unique<T>(bytecode, index, parser);
    }

    /// @brief table of opcodes and generator pointers
    /// generators are generated for each instruction
    std::unordered_map<DexOpcodes::opcodes, generator_func> function_pointers = {
            // Instruction00x
            {DexOpcodes::opcodes::OP_IGET_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IPUT_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_SGET_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_SPUT_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IGET_OBJECT_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IGET_WIDE_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IPUT_WIDE_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_SGET_WIDE_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_SPUT_WIDE_VOLATILE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_BREAKPOINT, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_THROW_VERIFICATION_ERROR, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_EXECUTE_INLINE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_EXECUTE_INLINE_RANGE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_INVOKE_OBJECT_INIT_RANGE, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_RETURN_VOID_BARRIER, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IGET_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IGET_WIDE_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IGET_OBJECT_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IPUT_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IPUT_WIDE_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_IPUT_OBJECT_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_INVOKE_VIRTUAL_QUICK, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_INVOKE_VIRTUAL_QUICK_RANGE, &get_instruction<Instruction00x>},
            // Instruction12x
            {DexOpcodes::opcodes::OP_MOVE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_MOVE_WIDE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_MOVE_OBJECT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_ARRAY_LENGTH, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_NEG_INT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_NOT_INT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_NEG_LONG, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_NOT_LONG, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_NEG_FLOAT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_NEG_DOUBLE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_INT_TO_LONG, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_INT_TO_FLOAT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_INT_TO_DOUBLE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_LONG_TO_INT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_LONG_TO_FLOAT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_LONG_TO_DOUBLE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_FLOAT_TO_INT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_FLOAT_TO_LONG, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_FLOAT_TO_DOUBLE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DOUBLE_TO_INT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DOUBLE_TO_LONG, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DOUBLE_TO_FLOAT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_INT_TO_BYTE, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_INT_TO_CHAR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_INT_TO_SHORT, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_ADD_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SUB_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_MUL_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DIV_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_REM_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_AND_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_OR_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_XOR_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SHL_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SHR_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_USHR_INT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_ADD_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SUB_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_MUL_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DIV_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_REM_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_AND_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_OR_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_XOR_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SHL_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SHR_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_USHR_LONG_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_ADD_FLOAT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SUB_FLOAT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_MUL_FLOAT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DIV_FLOAT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_REM_FLOAT_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_ADD_DOUBLE_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_SUB_DOUBLE_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_MUL_DOUBLE_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_DIV_DOUBLE_2ADDR, &get_instruction<Instruction12x>},
            {DexOpcodes::opcodes::OP_REM_DOUBLE_2ADDR, &get_instruction<Instruction12x>},
            // Instruction22x
            {DexOpcodes::opcodes::OP_MOVE_FROM16, &get_instruction<Instruction22x>},
            {DexOpcodes::opcodes::OP_MOVE_WIDE_FROM16, &get_instruction<Instruction22x>},
            {DexOpcodes::opcodes::OP_MOVE_OBJECT_FROM16, &get_instruction<Instruction22x>},
            // Instruction32x
            {DexOpcodes::opcodes::OP_MOVE_16, &get_instruction<Instruction32x>},
            {DexOpcodes::opcodes::OP_MOVE_WIDE_16, &get_instruction<Instruction32x>},
            {DexOpcodes::opcodes::OP_MOVE_OBJECT_16, &get_instruction<Instruction32x>},
            // Instruction11x
            {DexOpcodes::opcodes::OP_MOVE_RESULT, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_MOVE_RESULT_WIDE, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_MOVE_RESULT_OBJECT, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_MOVE_EXCEPTION, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_RETURN, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_RETURN_WIDE, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_RETURN_OBJECT, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_MONITOR_ENTER, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_MONITOR_EXIT, &get_instruction<Instruction11x>},
            {DexOpcodes::opcodes::OP_THROW, &get_instruction<Instruction11x>},
            // Instruction10x
            {DexOpcodes::opcodes::OP_RETURN_VOID, &get_instruction<Instruction10x>},
            {DexOpcodes::opcodes::OP_NOP, &get_instruction<Instruction10x>},
            // Instruction11n
            {DexOpcodes::opcodes::OP_CONST_4, &get_instruction<Instruction11n>},
            // Instruction21s
            {DexOpcodes::opcodes::OP_CONST_16, &get_instruction<Instruction21s>},
            {DexOpcodes::opcodes::OP_CONST_WIDE_16, &get_instruction<Instruction21s>},
            // Instruction31i
            {DexOpcodes::opcodes::OP_CONST, &get_instruction<Instruction31i>},
            {DexOpcodes::opcodes::OP_CONST_WIDE_32, &get_instruction<Instruction31i>},
            // Instruction21h
            {DexOpcodes::opcodes::OP_CONST_HIGH16, &get_instruction<Instruction21h>},
            {DexOpcodes::opcodes::OP_CONST_WIDE_HIGH16, &get_instruction<Instruction21h>},
            // Instruction51l
            {DexOpcodes::opcodes::OP_CONST_WIDE, &get_instruction<Instruction51l>},
            // Instruction21c
            {DexOpcodes::opcodes::OP_CONST_STRING, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_CONST_CLASS, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_CHECK_CAST, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_NEW_INSTANCE, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET_WIDE, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET_OBJECT, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET_BOOLEAN, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET_BYTE, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET_CHAR, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SGET_SHORT, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_WIDE, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_OBJECT, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_BOOLEAN, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_BYTE, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_CHAR, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_SHORT, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_SPUT_OBJECT_VOLATILE, &get_instruction<Instruction21c>},
            {DexOpcodes::opcodes::OP_CONST_METHOD_TYPE, &get_instruction<Instruction21c>},
            // Instruction31c
            {DexOpcodes::opcodes::OP_CONST_STRING_JUMBO, &get_instruction<Instruction31c>},
            // Instruction22c
            {DexOpcodes::opcodes::OP_INSTANCE_OF, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_NEW_ARRAY, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET_WIDE, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET_OBJECT, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET_BOOLEAN, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET_BYTE, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET_CHAR, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IGET_SHORT, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT_WIDE, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT_OBJECT, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT_BOOLEAN, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT_BYTE, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT_CHAR, &get_instruction<Instruction22c>},
            {DexOpcodes::opcodes::OP_IPUT_SHORT, &get_instruction<Instruction22c>},
            // Instruction35c
            {DexOpcodes::opcodes::OP_FILLED_NEW_ARRAY, &get_instruction<Instruction35c>},
            {DexOpcodes::opcodes::OP_INVOKE_VIRTUAL, &get_instruction<Instruction35c>},
            {DexOpcodes::opcodes::OP_INVOKE_SUPER, &get_instruction<Instruction35c>},
            {DexOpcodes::opcodes::OP_INVOKE_DIRECT, &get_instruction<Instruction35c>},
            {DexOpcodes::opcodes::OP_INVOKE_STATIC, &get_instruction<Instruction35c>},
            {DexOpcodes::opcodes::OP_INVOKE_INTERFACE, &get_instruction<Instruction35c>},
            // Instruction3rc
            {DexOpcodes::opcodes::OP_FILLED_NEW_ARRAY_RANGE, &get_instruction<Instruction3rc>},
            {DexOpcodes::opcodes::OP_INVOKE_VIRTUAL_RANGE, &get_instruction<Instruction3rc>},
            {DexOpcodes::opcodes::OP_INVOKE_SUPER_RANGE, &get_instruction<Instruction3rc>},
            {DexOpcodes::opcodes::OP_INVOKE_DIRECT_RANGE, &get_instruction<Instruction3rc>},
            {DexOpcodes::opcodes::OP_INVOKE_STATIC_RANGE, &get_instruction<Instruction3rc>},
            {DexOpcodes::opcodes::OP_INVOKE_INTERFACE_RANGE, &get_instruction<Instruction3rc>},
            // Instruction31t
            {DexOpcodes::opcodes::OP_FILL_ARRAY_DATA, &get_instruction<Instruction31t>},
            {DexOpcodes::opcodes::OP_PACKED_SWITCH, &get_instruction<Instruction31t>},
            {DexOpcodes::opcodes::OP_SPARSE_SWITCH, &get_instruction<Instruction31t>},
            // Instruction10t
            {DexOpcodes::opcodes::OP_GOTO, &get_instruction<Instruction10t>},
            // Instruction20t
            {DexOpcodes::opcodes::OP_GOTO_16, &get_instruction<Instruction20t>},
            // Instruction30t
            {DexOpcodes::opcodes::OP_GOTO_32, &get_instruction<Instruction30t>},
            // Instruction23x
            {DexOpcodes::opcodes::OP_CMPL_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_CMPG_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_CMPL_DOUBLE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_CMPG_DOUBLE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_CMP_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_ADD_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SUB_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_MUL_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_DIV_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_REM_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AND_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_OR_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_XOR_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SHL_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SHR_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_USHR_INT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_ADD_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SUB_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_MUL_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_DIV_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_REM_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AND_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_OR_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_XOR_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SHL_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SHR_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_USHR_LONG, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_ADD_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SUB_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_MUL_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_DIV_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_REM_FLOAT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_ADD_DOUBLE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_SUB_DOUBLE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_MUL_DOUBLE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_DIV_DOUBLE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_REM_DOUBLE, &get_instruction<Instruction23x>},
            // Instruction22t
            {DexOpcodes::opcodes::OP_IF_EQ, &get_instruction<Instruction22t>},
            {DexOpcodes::opcodes::OP_IF_NE, &get_instruction<Instruction22t>},
            {DexOpcodes::opcodes::OP_IF_LT, &get_instruction<Instruction22t>},
            {DexOpcodes::opcodes::OP_IF_GE, &get_instruction<Instruction22t>},
            {DexOpcodes::opcodes::OP_IF_GT, &get_instruction<Instruction22t>},
            {DexOpcodes::opcodes::OP_IF_LE, &get_instruction<Instruction22t>},
            // Instruction21t
            {DexOpcodes::opcodes::OP_IF_EQZ, &get_instruction<Instruction21t>},
            {DexOpcodes::opcodes::OP_IF_NEZ, &get_instruction<Instruction21t>},
            {DexOpcodes::opcodes::OP_IF_LTZ, &get_instruction<Instruction21t>},
            {DexOpcodes::opcodes::OP_IF_GEZ, &get_instruction<Instruction21t>},
            {DexOpcodes::opcodes::OP_IF_GTZ, &get_instruction<Instruction21t>},
            {DexOpcodes::opcodes::OP_IF_LEZ, &get_instruction<Instruction21t>},
            // Instruction00x
            {DexOpcodes::opcodes::OP_UNUSED_3E, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_3F, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_40, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_41, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_42, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_43, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_73, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_79, &get_instruction<Instruction00x>},
            {DexOpcodes::opcodes::OP_UNUSED_7A, &get_instruction<Instruction00x>},
            // Instruction23x
            {DexOpcodes::opcodes::OP_AGET, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AGET_WIDE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AGET_OBJECT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AGET_BOOLEAN, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AGET_BYTE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AGET_CHAR, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_AGET_SHORT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT_WIDE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT_OBJECT, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT_BOOLEAN, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT_BYTE, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT_CHAR, &get_instruction<Instruction23x>},
            {DexOpcodes::opcodes::OP_APUT_SHORT, &get_instruction<Instruction23x>},
            // Instruction22s
            {DexOpcodes::opcodes::OP_ADD_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_SUB_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_MUL_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_DIV_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_REM_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_AND_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_OR_INT_LIT16, &get_instruction<Instruction22s>},
            {DexOpcodes::opcodes::OP_XOR_INT_LIT16, &get_instruction<Instruction22s>},
            // Instruction22b
            {DexOpcodes::opcodes::OP_ADD_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_SUB_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_MUL_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_DIV_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_REM_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_AND_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_OR_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_XOR_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_SHL_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_SHR_INT_LIT8, &get_instruction<Instruction22b>},
            {DexOpcodes::opcodes::OP_USHR_INT_LIT8, &get_instruction<Instruction22b>},
            // Instruction45cc
            {DexOpcodes::opcodes::OP_INVOKE_SUPER_QUICK, &get_instruction<Instruction45cc>},
            // Instruction4rcc
            {DexOpcodes::opcodes::OP_INVOKE_SUPER_QUICK_RANGE, &get_instruction<Instruction4rcc>},
            // Instruction35c
            {DexOpcodes::opcodes::OP_IPUT_OBJECT_VOLATILE, &get_instruction<Instruction35c>},
            // Instruction3rc
            {DexOpcodes::opcodes::OP_SGET_OBJECT_VOLATILE, &get_instruction<Instruction3rc>},
    };
}// namespace

Disassembler::Disassembler(parser::dex::Parser *parser)
    : parser(parser) {
}

std::unique_ptr<Instruction> Disassembler::disassemble_instruction(
        std::uint32_t opcode,
        std::span<uint8_t> bytecode,
        std::size_t index) {
    auto op = static_cast<DexOpcodes::opcodes>(opcode);

    std::unique_ptr<Instruction> instr = nullptr;
    auto logger = shuriken::logger();

    if (DexOpcodes::opcodes::OP_NOP == op) {
        auto second_opcode = bytecode[index + 1];

        if (second_opcode == 0x03)// filled-array-data
            instr = ::get_instruction<FillArrayData>(bytecode, index, parser);
        else if (second_opcode == 0x01)// packed-switch-data
            instr = ::get_instruction<PackedSwitch>(bytecode, index, parser);
        else if (second_opcode == 0x02)// sparse-switch-data
            instr = ::get_instruction<SparseSwitch>(bytecode, index, parser);
        else
            instr = ::function_pointers[DexOpcodes::opcodes::OP_NOP](bytecode, index, parser);
    } else {
        auto it = ::function_pointers.find(static_cast<DexOpcodes::opcodes>(opcode));

        if (it != ::function_pointers.end())
            instr = it->second(bytecode, index, parser);

        else {
            logger->error("Error in disassembler, opcode {} not recognized", opcode);
            throw std::runtime_error("Error in disassembler, not recognized opcode");
        }
    }

    /// save the backup instruction
    if (instr)
        last_instr = instr.get();

    return instr;
}

std::vector<std::int64_t> Disassembler::determine_next(Instruction *instruction,
                                                       std::uint64_t curr_idx) {
    if (!instruction)
        return {};

    auto op_code = static_cast<DexOpcodes::opcodes>(instruction->get_instruction_opcode());

    // an operation of return, since we are only analyzing
    // one method, we do not know where it takes us...
    if ((op_code >= DexOpcodes::opcodes::OP_RETURN_VOID) &&
        (op_code <= DexOpcodes::opcodes::OP_RETURN_OBJECT)) {
        return {-1};
    }

    // GOTOs only have one target, since it is an unconditional
    // jump
    if (op_code >= DexOpcodes::opcodes::OP_GOTO &&
        op_code <= DexOpcodes::opcodes::OP_GOTO_32) {
        std::int32_t offset = 0;

        if (op_code == DexOpcodes::opcodes::OP_GOTO) {
            auto goto_instr = reinterpret_cast<Instruction10t *>(instruction);
            offset = goto_instr->get_offset();
        } else if (op_code == DexOpcodes::opcodes::OP_GOTO_16) {
            auto goto_instr = reinterpret_cast<Instruction20t *>(instruction);
            offset = goto_instr->get_offset();
        } else if (op_code == DexOpcodes::opcodes::OP_GOTO_32) {
            auto goto_instr = reinterpret_cast<Instruction30t *>(instruction);
            offset = goto_instr->get_offset();
        }

        return {(offset * 2) + static_cast<std::int64_t>(curr_idx)};
    }

    // in the case of the conditional jumps we will have the fallthrough
    // target, and the one taken in case the condition is met
    if (op_code >= DexOpcodes::opcodes::OP_IF_EQ &&
        op_code <= DexOpcodes::opcodes::OP_IF_LEZ) {
        std::int32_t offset = 0;

        if (op_code >= DexOpcodes::opcodes::OP_IF_EQ &&
            op_code <= DexOpcodes::opcodes::OP_IF_LE) {
            auto if_instr = reinterpret_cast<Instruction22t *>(instruction);
            offset = if_instr->get_offset();
        } else if (op_code >= DexOpcodes::opcodes::OP_IF_EQZ &&
                   op_code <= DexOpcodes::opcodes::OP_IF_LEZ) {
            auto if_instr = reinterpret_cast<Instruction21t *>(instruction);
            offset = if_instr->get_jump_offset();
        }

        return {
                static_cast<std::int64_t>(curr_idx) + instruction->get_instruction_length(),// fallthrough
                static_cast<std::int64_t>(curr_idx) + (offset * 2)                          // target of the jump
        };
    }

    // finally the switch instructions will have multiple
    // targets, including the one after the instruction
    if (op_code == DexOpcodes::opcodes::OP_PACKED_SWITCH ||
        op_code == DexOpcodes::opcodes::OP_SPARSE_SWITCH) {
        std::vector<std::int64_t> x = {static_cast<std::int64_t>(curr_idx) +
                                       instruction->get_instruction_length()};

        auto switch_instr = reinterpret_cast<Instruction31t *>(instruction);

        switch (switch_instr->get_type_of_switch()) {
            case PACKED_SWITCH: {
                auto packed_switch = std::get<PackedSwitch *>(switch_instr->get_switch());
                const auto &targets = packed_switch->get_targets();

                for (auto &target: targets)
                    x.push_back(curr_idx + target * 2);
            } break;
            case SPARSE_SWITCH: {
                auto sparse_switch = std::get<SparseSwitch *>(switch_instr->get_switch());
                const auto &keys_targets = sparse_switch->get_keys_targets();

                for (auto &key_target: keys_targets)
                    x.push_back(curr_idx + std::get<1>(key_target) * 2);
            } break;
            default:
                throw std::runtime_error("disassembler.cpp::determine_next: switch instruction not recognized");
        }

        return x;
    }

    // no other case, only the fallthrough of the instruction
    return {static_cast<int64_t>(curr_idx + instruction->get_instruction_length())};
}

std::vector<std::int64_t> Disassembler::determine_next(std::uint64_t curr_idx) {
    return determine_next(last_instr, curr_idx);
}

std::int16_t Disassembler::get_conditional_jump_target(Instruction *instr) {
    if (!instr)
        return 0;

    auto op_code = static_cast<DexOpcodes::opcodes>(instr->get_instruction_opcode());

    if (InstructionUtils::get_operation_type_from_opcode(op_code) !=
        DexOpcodes::operation_type::CONDITIONAL_BRANCH_DVM_OPCODE)
        return 0;

    switch (op_code) {
        case DexOpcodes::opcodes::OP_IF_EQ:
        case DexOpcodes::opcodes::OP_IF_NE:// "if-ne"
        case DexOpcodes::opcodes::OP_IF_LT:// "if-lt"
        case DexOpcodes::opcodes::OP_IF_GE:// "if-ge"
        case DexOpcodes::opcodes::OP_IF_GT:// "if-gt"
        case DexOpcodes::opcodes::OP_IF_LE:// "if-le"
        {
            auto instr22t = reinterpret_cast<Instruction22t *>(instr);
            return instr22t->get_offset();
        }
        case DexOpcodes::opcodes::OP_IF_EQZ:// "if-eqz"
        case DexOpcodes::opcodes::OP_IF_NEZ:// "if-nez"
        case DexOpcodes::opcodes::OP_IF_LTZ:// "if-ltz"
        case DexOpcodes::opcodes::OP_IF_GEZ:// "if-gez"
        case DexOpcodes::opcodes::OP_IF_GTZ:// "if-gtz"
        case DexOpcodes::opcodes::OP_IF_LEZ:// "if-lez"
        {
            auto instr21t = reinterpret_cast<Instruction21t *>(instr);
            return instr21t->get_jump_offset();
        }
        default:
            return 0;
    }
}

std::int32_t Disassembler::get_unconditional_jump_target(Instruction *instr) {
    if (!instr)
        return 0;

    auto op_code = static_cast<DexOpcodes::opcodes>(instr->get_instruction_opcode());

    if (InstructionUtils::get_operation_type_from_opcode(op_code) !=
        DexOpcodes::operation_type::UNCONDITIONAL_BRANCH_DVM_OPCODE)
        return 0;

    switch (op_code) {
        case DexOpcodes::opcodes::OP_GOTO: {
            auto goto_instr = reinterpret_cast<Instruction10t *>(instr);
            return goto_instr->get_offset();
        }
        case DexOpcodes::opcodes::OP_GOTO_16: {
            auto goto16_instr = reinterpret_cast<Instruction20t *>(instr);
            return goto16_instr->get_offset();
        }
        case DexOpcodes::opcodes::OP_GOTO_32: {
            auto goto32_instr = reinterpret_cast<Instruction30t *>(instr);
            return goto32_instr->get_offset();
        }
        default:
            return 0;
    }
}

std::vector<exception_data_t> Disassembler::determine_exception(parser::dex::EncodedMethod *method) {
    /// pair of TryItem and EncodedCatchHandlers
    using try_encoded = std::pair<parser::dex::TryItem *, parser::dex::EncodedCatchHandler *>;
    /// vector of pairs
    using vector_try_encoded = std::vector<try_encoded>;

    std::unordered_map<std::uint64_t, vector_try_encoded> h_off;

    exceptions_data_t exceptions;

    /// check for the EncodedMethod
    if (!method || !method->get_code_item()->get_number_try_items())
        return {};

    auto code_item = method->get_code_item();

    // retrieve all the try items with the handler
    // of the offset
    for (auto &try_item: code_item->get_try_items()) {
        auto offset_handler = try_item.handler_off +
                              code_item->get_encoded_catch_handler_offset();
        h_off[offset_handler].push_back({&try_item, nullptr});
    }

    // add the encoded catch handlers to the structure
    for (auto &encoded_catch_handler: code_item->get_encoded_catch_handlers()) {
        auto it = h_off.find(encoded_catch_handler.get_offset());

        if (it == h_off.end())
            continue;

        for (auto &v: it->second)
            v.second = &encoded_catch_handler;
    }

    // now create the exceptions structure
    for (auto &off_values: h_off) {
        for (auto &values: off_values.second) {
            auto try_value = values.first;
            auto handler_catch = values.second;

            exception_data_t z;

            z.try_value_start_addr = try_value->start_addr * 2;
            z.try_value_end_addr = (try_value->start_addr * 2) +
                                   (try_value->insn_count * 2);

            for (auto &catch_type_pair: handler_catch->get_handle_pairs())
                z.handler.push_back({catch_type_pair.type, catch_type_pair.idx * 2});

            exceptions.emplace_back(z);
        }
    }

    return exceptions;
}