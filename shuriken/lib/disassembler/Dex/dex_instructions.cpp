//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_instructions.cpp

#include "shuriken/disassembler/Dex/dex_instructions.h"
#include "shuriken/exceptions/invalidinstruction_exception.h"

#include <algorithm>
#include <sstream>

using namespace shuriken::disassembler::dex;

namespace {

    /// @brief Names for each one of the previously
    /// defined opcodes from the DVM.
    static const  std::unordered_map<DexOpcodes::opcodes, std::string>
            opcode_names {
#define INST_NAME(OP, NAME) \
                    {OP, NAME},
#include "shuriken/disassembler/Dex/definitions/dvm_inst_names.def"
};

    /// @brief Map of the opcodes with the Kind of argument
    /// inside of the operation
    static const std::unordered_map<DexOpcodes::opcodes, shuriken::dex::TYPES::kind>
            opcodes_instruction_kind {
#define INST_KIND(OP, VAL) {OP, VAL},
#include "shuriken/disassembler/Dex/definitions/dvm_inst_kind.def"
        };

    /// @brief Map of the opcodes with the type of the operation
    /// from the instruction
    static const std::unordered_map<DexOpcodes::opcodes, DexOpcodes::operation_type>
            opcodes_instruction_operation {
#define INST_OP(OP, VAL) {OP, VAL},
#include "shuriken/disassembler/Dex/definitions/dvm_inst_operation.def"
        };

    /// @brief Opcodes that has some kind of side effect
    const std::vector<DexOpcodes::opcodes> side_effects_opcodes {
        DexOpcodes::opcodes::OP_RETURN_VOID,
        DexOpcodes::opcodes::OP_RETURN,
        DexOpcodes::opcodes::OP_RETURN_WIDE,
        DexOpcodes::opcodes::OP_RETURN_OBJECT,
        DexOpcodes::opcodes::OP_MONITOR_ENTER,
        DexOpcodes::opcodes::OP_MONITOR_EXIT,
        DexOpcodes::opcodes::OP_FILL_ARRAY_DATA,
        DexOpcodes::opcodes::OP_THROW,
        DexOpcodes::opcodes::OP_GOTO,
        DexOpcodes::opcodes::OP_SPARSE_SWITCH,
        DexOpcodes::opcodes::OP_PACKED_SWITCH,
        DexOpcodes::opcodes::OP_IF_EQ,
        DexOpcodes::opcodes::OP_IF_NE,
        DexOpcodes::opcodes::OP_IF_LT,
        DexOpcodes::opcodes::OP_IF_GE,
        DexOpcodes::opcodes::OP_IF_GT,
        DexOpcodes::opcodes::OP_IF_LE,
        DexOpcodes::opcodes::OP_IF_EQZ,
        DexOpcodes::opcodes::OP_IF_NEZ,
        DexOpcodes::opcodes::OP_IF_LTZ,
        DexOpcodes::opcodes::OP_IF_GEZ,
        DexOpcodes::opcodes::OP_IF_GTZ,
        DexOpcodes::opcodes::OP_IF_LEZ,
        DexOpcodes::opcodes::OP_APUT,
        DexOpcodes::opcodes::OP_APUT_WIDE,
        DexOpcodes::opcodes::OP_APUT_OBJECT,
        DexOpcodes::opcodes::OP_APUT_BOOLEAN,
        DexOpcodes::opcodes::OP_APUT_BYTE,
        DexOpcodes::opcodes::OP_APUT_CHAR,
        DexOpcodes::opcodes::OP_APUT_SHORT,
        DexOpcodes::opcodes::OP_IPUT,
        DexOpcodes::opcodes::OP_IPUT_WIDE,
        DexOpcodes::opcodes::OP_IPUT_OBJECT,
        DexOpcodes::opcodes::OP_IPUT_BOOLEAN,
        DexOpcodes::opcodes::OP_IPUT_BYTE,
        DexOpcodes::opcodes::OP_IPUT_CHAR,
        DexOpcodes::opcodes::OP_IPUT_SHORT,
        DexOpcodes::opcodes::OP_SPUT,
        DexOpcodes::opcodes::OP_SPUT_WIDE,
        DexOpcodes::opcodes::OP_SPUT_OBJECT,
        DexOpcodes::opcodes::OP_SPUT_BOOLEAN,
        DexOpcodes::opcodes::OP_SPUT_BYTE,
        DexOpcodes::opcodes::OP_SPUT_CHAR,
        DexOpcodes::opcodes::OP_SPUT_SHORT,
        DexOpcodes::opcodes::OP_INVOKE_VIRTUAL,
        DexOpcodes::opcodes::OP_INVOKE_SUPER,
        DexOpcodes::opcodes::OP_INVOKE_DIRECT,
        DexOpcodes::opcodes::OP_INVOKE_STATIC,
        DexOpcodes::opcodes::OP_INVOKE_INTERFACE,
    };

    /// @brief Opcodes that may throw an exception
    const std::vector<DexOpcodes::opcodes> may_throw_opcodes {
        DexOpcodes::opcodes::OP_CONST_STRING,
        DexOpcodes::opcodes::OP_CONST_CLASS,
        DexOpcodes::opcodes::OP_MONITOR_ENTER,
        DexOpcodes::opcodes::OP_MONITOR_EXIT,
        DexOpcodes::opcodes::OP_CHECK_CAST,
        DexOpcodes::opcodes::OP_INSTANCE_OF,
        DexOpcodes::opcodes::OP_ARRAY_LENGTH,
        DexOpcodes::opcodes::OP_NEW_INSTANCE,
        DexOpcodes::opcodes::OP_NEW_ARRAY,
        DexOpcodes::opcodes::OP_FILLED_NEW_ARRAY,
        DexOpcodes::opcodes::OP_AGET,
        DexOpcodes::opcodes::OP_AGET_WIDE,
        DexOpcodes::opcodes::OP_AGET_OBJECT,
        DexOpcodes::opcodes::OP_AGET_BOOLEAN,
        DexOpcodes::opcodes::OP_AGET_BYTE,
        DexOpcodes::opcodes::OP_AGET_CHAR,
        DexOpcodes::opcodes::OP_AGET_SHORT,
        DexOpcodes::opcodes::OP_APUT,
        DexOpcodes::opcodes::OP_APUT_WIDE,
        DexOpcodes::opcodes::OP_APUT_OBJECT,
        DexOpcodes::opcodes::OP_APUT_BOOLEAN,
        DexOpcodes::opcodes::OP_APUT_BYTE,
        DexOpcodes::opcodes::OP_APUT_CHAR,
        DexOpcodes::opcodes::OP_APUT_SHORT,
        DexOpcodes::opcodes::OP_IGET,
        DexOpcodes::opcodes::OP_IGET_WIDE,
        DexOpcodes::opcodes::OP_IGET_OBJECT,
        DexOpcodes::opcodes::OP_IGET_BOOLEAN,
        DexOpcodes::opcodes::OP_IGET_BYTE,
        DexOpcodes::opcodes::OP_IGET_CHAR,
        DexOpcodes::opcodes::OP_IGET_SHORT,
        DexOpcodes::opcodes::OP_IPUT,
        DexOpcodes::opcodes::OP_IPUT_WIDE,
        DexOpcodes::opcodes::OP_IPUT_OBJECT,
        DexOpcodes::opcodes::OP_IPUT_BOOLEAN,
        DexOpcodes::opcodes::OP_IPUT_BYTE,
        DexOpcodes::opcodes::OP_IPUT_CHAR,
        DexOpcodes::opcodes::OP_IPUT_SHORT,
        DexOpcodes::opcodes::OP_SGET,
        DexOpcodes::opcodes::OP_SGET_WIDE,
        DexOpcodes::opcodes::OP_SGET_OBJECT,
        DexOpcodes::opcodes::OP_SGET_BOOLEAN,
        DexOpcodes::opcodes::OP_SGET_BYTE,
        DexOpcodes::opcodes::OP_SGET_CHAR,
        DexOpcodes::opcodes::OP_SGET_SHORT,
        DexOpcodes::opcodes::OP_SPUT,
        DexOpcodes::opcodes::OP_SPUT_WIDE,
        DexOpcodes::opcodes::OP_SPUT_OBJECT,
        DexOpcodes::opcodes::OP_SPUT_BOOLEAN,
        DexOpcodes::opcodes::OP_SPUT_BYTE,
        DexOpcodes::opcodes::OP_SPUT_CHAR,
        DexOpcodes::opcodes::OP_SPUT_SHORT,
        DexOpcodes::opcodes::OP_INVOKE_VIRTUAL,
        DexOpcodes::opcodes::OP_INVOKE_SUPER,
        DexOpcodes::opcodes::OP_INVOKE_DIRECT,
        DexOpcodes::opcodes::OP_INVOKE_STATIC,
        DexOpcodes::opcodes::OP_INVOKE_INTERFACE,
        DexOpcodes::opcodes::OP_DIV_INT,
        DexOpcodes::opcodes::OP_REM_INT,
        DexOpcodes::opcodes::OP_DIV_LONG,
        DexOpcodes::opcodes::OP_REM_LONG,
        DexOpcodes::opcodes::OP_DIV_INT_LIT16,
        DexOpcodes::opcodes::OP_REM_INT_LIT16,
        DexOpcodes::opcodes::OP_DIV_INT_LIT8,
        DexOpcodes::opcodes::OP_REM_INT_LIT8,
    };

    std::string get_kind_type_as_string(kind_type_t source_id, std::uint16_t iBBBB) {
        std::string instruction_str = "";

        if (std::holds_alternative<std::monostate>(source_id)) {
            instruction_str += " // UNKNOWN@" + std::to_string(iBBBB);
        } else if (std::holds_alternative<shuriken::parser::dex::DVMType*>(source_id)) {
            auto type = std::get<shuriken::parser::dex::DVMType*>(source_id);
            instruction_str += type->get_raw_type();
            instruction_str += " // type@" + std::to_string(iBBBB);
        } else if (std::holds_alternative<shuriken::parser::dex::FieldID*>(source_id)) {
            auto field = std::get<shuriken::parser::dex::FieldID*>(source_id);
            instruction_str += field->pretty_field();
            instruction_str += " // field@" + std::to_string(iBBBB);
        } else if (std::holds_alternative<shuriken::parser::dex::MethodID*>(source_id)) {
            auto method = std::get<shuriken::parser::dex::MethodID*>(source_id);
            instruction_str += method->dalvik_name_format();
            instruction_str += " // method@" + std::to_string(iBBBB);
        } else if (std::holds_alternative<shuriken::parser::dex::ProtoID*>(source_id)) {
            auto proto = std::get<shuriken::parser::dex::ProtoID*>(source_id);
            instruction_str += proto->get_shorty_idx();
            instruction_str += " // proto@" + std::to_string(iBBBB);
        } else if (std::holds_alternative<std::string_view>(source_id)) {
            auto str = std::get<std::string_view>(source_id);
            instruction_str += "\"";
            instruction_str += str;
            instruction_str += "\"";
            instruction_str += " // string@" + std::to_string(iBBBB);
        }

        return instruction_str;
    }
};

DexOpcodes::operation_type InstructionUtils::get_operation_type_from_opcode(DexOpcodes::opcodes opcode) {
    if (opcodes_instruction_operation.find(opcode) == opcodes_instruction_operation.end())
        return DexOpcodes::operation_type::NONE_OPCODE;
    return opcodes_instruction_operation.at(opcode);
}

Instruction::Instruction(std::span<uint8_t> bytecode, std::size_t index, DexOpcodes::dexinsttype instruction_type)
        : instruction_type(instruction_type), length(0), op(0), op_codes({}) {
}

Instruction::Instruction(std::span<uint8_t> bytecode, std::size_t index, DexOpcodes::dexinsttype instruction_type, std::uint32_t length)
        : instruction_type(instruction_type), length(length), op(0), op_codes({bytecode.begin() + index, bytecode.begin() + index + length}) {
}

shuriken::dex::TYPES::kind Instruction::get_kind() const {
    auto it = opcodes_instruction_kind.find(static_cast<DexOpcodes::opcodes>(op));

    if (it == opcodes_instruction_kind.end())
        return shuriken::dex::TYPES::kind::NONE_KIND;

    return it->second;
}

DexOpcodes::dexinsttype Instruction::get_instruction_type() const {
    return instruction_type;
}

std::uint32_t Instruction::get_instruction_length() const {
    return length;
}

std::uint32_t Instruction::get_instruction_opcode() const {
    return op;
}

void Instruction::set_address(std::uint64_t address) {
    this->address = address;
}

std::uint64_t Instruction::get_address() const {
    return address;
}

std::span<std::uint8_t> Instruction::get_opcodes() {
    return op_codes;
}

bool Instruction::is_terminator() {
    auto operation = opcodes_instruction_operation.at(static_cast<DexOpcodes::opcodes>(op));

    if (operation == DexOpcodes::operation_type::CONDITIONAL_BRANCH_DVM_OPCODE ||
        operation == DexOpcodes::operation_type::UNCONDITIONAL_BRANCH_DVM_OPCODE ||
        operation == DexOpcodes::operation_type::RET_BRANCH_DVM_OPCODE ||
        operation == DexOpcodes::operation_type::MULTI_BRANCH_DVM_OPCODE)
        return true;

    return false;
}

bool Instruction::has_side_effects() const {
    const auto dex_op = static_cast<DexOpcodes::opcodes>(op);
    if (std::find(side_effects_opcodes.begin(), side_effects_opcodes.end(), dex_op)
            != side_effects_opcodes.end())
        return true;
    return false;
}

bool Instruction::may_throw() const {
    const auto dex_op = static_cast<DexOpcodes::opcodes>(op);
    if (std::find(may_throw_opcodes.begin(), may_throw_opcodes.end(), dex_op)
        != may_throw_opcodes.end())
        return true;
    return false;
}

Instruction00x::Instruction00x(std::span<uint8_t> bytecode, std::size_t index)
        : Instruction00x(bytecode, index, nullptr) {
}

Instruction00x::Instruction00x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION00X) {
}

std::string_view Instruction00x::print_instruction() {
    if (instruction_str.empty())
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
    return instruction_str;
}

void Instruction00x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction10x::Instruction10x(std::span<uint8_t> bytecode, std::size_t index) :
        Instruction10x(bytecode, index, nullptr) {
}

Instruction10x::Instruction10x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION10X, 2) {
    if (op_codes[1] != 0)
        throw exceptions::InvalidInstructionException("Instruction10x high byte should be 0", 2);
    op = op_codes[0];
}

std::string_view Instruction10x::print_instruction() {
    if (instruction_str.empty())
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
    return instruction_str;
}

void Instruction10x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction12x::Instruction12x(std::span<uint8_t> bytecode, std::size_t index) :
    Instruction12x(bytecode, index, nullptr) {
}

Instruction12x::Instruction12x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION12X, 2) {
    op = op_codes[0];
    vA = (op_codes[1] & 0x0F);
    vB = (op_codes[1] & 0xF0) >> 4;
}

std::uint8_t Instruction12x::get_destination() const {
    return vA;
}

DexOpcodes::operand_type Instruction12x::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction12x::get_source() const {
    return vB;
}

DexOpcodes::operand_type Instruction12x::get_source_type() const {
    return DexOpcodes::REGISTER;
}

std::string_view Instruction12x::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vA);
        instruction_str += ", ";
        instruction_str += "v" + std::to_string(vB);
    }
    return instruction_str;
}

void Instruction12x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction11n::Instruction11n(std::span<uint8_t> bytecode, std::size_t index) :
        Instruction11n(bytecode, index, nullptr) {
}

Instruction11n::Instruction11n(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION11N, 2) {
    op = op_codes[0];
    vA = op_codes[1] & 0x0F;
    nB = static_cast<std::int8_t>((op_codes[1] & 0xF0) >> 4);
}

std::uint8_t Instruction11n::get_destination() const {
    return vA;
}

DexOpcodes::operand_type Instruction11n::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::int8_t Instruction11n::get_source() const {
    return nB;
}

DexOpcodes::operand_type Instruction11n::get_source_type() const {
    return DexOpcodes::LITERAL;
}

std::string_view Instruction11n::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vA);
        instruction_str += ", ";
        instruction_str += std::to_string(nB);
    }

    return instruction_str;
}

void Instruction11n::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction11x::Instruction11x(std::span<uint8_t> bytecode, std::size_t index) :
    Instruction11x(bytecode, index, nullptr) {
}

Instruction11x::Instruction11x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
        : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION11X, 2) {
    op = op_codes[0];
    vAA = op_codes[1];
}

std::uint8_t Instruction11x::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction11x::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::string_view Instruction11x::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
    }

    return instruction_str;
}

void Instruction11x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction10t::Instruction10t(std::span<uint8_t> bytecode, std::size_t index) :
    Instruction10t(bytecode, index, nullptr) {
}

Instruction10t::Instruction10t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION10T, 2) {
    op = op_codes[0];
    nAA = static_cast<std::int8_t>(op_codes[1]);
}

std::int8_t Instruction10t::get_offset() const {
    return nAA;
}

DexOpcodes::operand_type Instruction10t::get_operand_type() const {
    return DexOpcodes::OFFSET;
}

std::string_view Instruction10t::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += std::to_string((nAA*2) + static_cast<std::int64_t>(address));
    }
    return instruction_str;
}

void Instruction10t::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction20t::Instruction20t(std::span<uint8_t> bytecode, std::size_t index) :
        Instruction20t(bytecode, index, nullptr) {
}

Instruction20t::Instruction20t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION10T, 4) {
    if (op_codes[1] != 0)
        throw exceptions::InvalidInstructionException("Error reading Instruction20t padding must be 0", 4);
    op = op_codes[0];
    nAAAA = *(reinterpret_cast<std::int16_t *>(&op_codes[2]));
}

std::int16_t Instruction20t::get_offset() const {
    return nAAAA;
}

DexOpcodes::operand_type Instruction20t::get_operand_type() const {
    return DexOpcodes::OFFSET;
}

std::string_view Instruction20t::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += std::to_string((nAAAA*2) + static_cast<std::int64_t>(address));
    }
    return instruction_str;
}

void Instruction20t::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction20bc::Instruction20bc(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction20bc(bytecode, index, nullptr) {
}

Instruction20bc::Instruction20bc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION20BC, 4) {
    op = op_codes[0];
    nAA = op_codes[1];
    nBBBB = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
}

std::uint8_t Instruction20bc::get_type_of_error_data() const {
    return nAA;
}

DexOpcodes::operand_type Instruction20bc::get_error_operand_type() const {
    return DexOpcodes::LITERAL;
}

std::uint16_t Instruction20bc::get_index_into_table() const {
    return nBBBB;
}

DexOpcodes::operand_type Instruction20bc::get_index_operand_type() const {
    return DexOpcodes::KIND;
}

std::string_view Instruction20bc::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += std::to_string(nAA);
        instruction_str += ", kind@" + std::to_string(nBBBB);
    }
    return instruction_str;
}

void Instruction20bc::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction22x::Instruction22x(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction22x(bytecode, index, nullptr) {
}

Instruction22x::Instruction22x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION22X, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    vBBBB = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
}

std::uint8_t Instruction22x::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction22x::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint16_t Instruction22x::get_source() const {
    return vBBBB;
}

DexOpcodes::operand_type Instruction22x::get_source_type() const {
    return DexOpcodes::REGISTER;
}

std::string_view Instruction22x::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
        instruction_str += ", v" + std::to_string(vBBBB);
    }
    return instruction_str;
}

void Instruction22x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction21t::Instruction21t(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction21t(bytecode, index, nullptr) {
}

Instruction21t::Instruction21t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION21T, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    nBBBB = *(reinterpret_cast<std::int16_t *>(&op_codes[2]));

    if (nBBBB == 0)
        throw exceptions::InvalidInstructionException("Error reading Instruction21t offset cannot be 0", 4);
}

std::uint8_t Instruction21t::get_check_reg() const {
    return vAA;
}

DexOpcodes::operand_type Instruction21t::get_check_reg_type() const {
    return DexOpcodes::REGISTER;
}

std::int16_t Instruction21t::get_jump_offset() const {
    return nBBBB;
}

DexOpcodes::operand_type Instruction21t::get_offset_type() const {
    return DexOpcodes::OFFSET;
}

std::string_view Instruction21t::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
        instruction_str += ", " + std::to_string(nBBBB);
    }
    return instruction_str;
}

void Instruction21t::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction21s::Instruction21s(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction21s(bytecode, index, nullptr) {
}

Instruction21s::Instruction21s(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION21S, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    nBBBB = *(reinterpret_cast<std::int16_t *>(&op_codes[2]));
}

std::uint8_t Instruction21s::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction21s::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::int16_t Instruction21s::get_source() const {
    return nBBBB;
}

DexOpcodes::operand_type Instruction21s::get_source_type() const {
    return DexOpcodes::OFFSET;
}

std::string_view Instruction21s::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " v";
        instruction_str += std::to_string(vAA);
        instruction_str += ", " + std::to_string(nBBBB);
    }
    return instruction_str;
}

void Instruction21s::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction21h::Instruction21h(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction21h(bytecode, index, nullptr) {
}

Instruction21h::Instruction21h(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION21H, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    nBBBB = *(reinterpret_cast<std::int16_t *>(&op_codes[2]));

    switch (static_cast<DexOpcodes::opcodes>(op)) {
        case DexOpcodes::opcodes::OP_CONST_HIGH16:
            nBBBB = nBBBB << 16;
            break;
        case DexOpcodes::opcodes::OP_CONST_WIDE_HIGH16:
            nBBBB = nBBBB << 48;
            break;
    }
}

std::uint8_t Instruction21h::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction21h::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::int64_t Instruction21h::get_source() const {
    return nBBBB;
}

DexOpcodes::operand_type Instruction21h::get_source_type() const {
    return DexOpcodes::LITERAL;
}

std::string_view Instruction21h::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
        instruction_str += ", " + std::to_string(nBBBB);
    }
    return instruction_str;
}

void Instruction21h::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction21c::Instruction21c(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction21c(bytecode, index, nullptr) {
}

Instruction21c::Instruction21c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION21C, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    iBBBB = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    source_id = std::monostate{};

    if (parser == nullptr) return;

    /// The instruction has a kind of operation depending
    /// on the op code, check it, and use it wisely
    switch (get_kind()) {
        case shuriken::dex::TYPES::STRING:
            source_id = parser->get_strings().get_string_by_id(iBBBB);
            break;
        case shuriken::dex::TYPES::TYPE:
            source_id = parser->get_types().get_type_by_id(iBBBB);
            break;
        case shuriken::dex::TYPES::FIELD:
            source_id = parser->get_fields().get_field_by_id(iBBBB);
            break;
        case shuriken::dex::TYPES::METH:
            source_id = parser->get_methods().get_method_by_id(iBBBB);
            break;
        case shuriken::dex::TYPES::PROTO:
            source_id = parser->get_protos().get_proto_by_id(iBBBB);
            break;
    }
}

std::uint8_t Instruction21c::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction21c::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint16_t Instruction21c::get_source() const {
    return iBBBB;
}

DexOpcodes::operand_type Instruction21c::get_source_type() const {
    return DexOpcodes::KIND;
}

shuriken::dex::TYPES::kind Instruction21c::get_source_kind() const {
    return get_kind();
}

kind_type_t Instruction21c::get_source_as_kind() const {
    return source_id;
}

std::string_view Instruction21c::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
        instruction_str += ", ";
        instruction_str += get_kind_type_as_string(source_id, iBBBB);
    }
    return instruction_str;
}

void Instruction21c::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction23x::Instruction23x(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction23x(bytecode, index, nullptr) {
}

Instruction23x::Instruction23x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION23X, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    vBB = op_codes[2];
    vCC = op_codes[3];
}

std::uint8_t Instruction23x::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction23x::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction23x::get_first_source() const {
    return vBB;
}

DexOpcodes::operand_type Instruction23x::get_first_source_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction23x::get_second_source() const {
    return vCC;
}

DexOpcodes::operand_type Instruction23x::get_second_source_type() const {
    return DexOpcodes::REGISTER;
}

std::string_view Instruction23x::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
        instruction_str += ", v" + std::to_string(vBB);
        instruction_str += ", v" + std::to_string(vCC);
    }
    return instruction_str;
}

void Instruction23x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction22b::Instruction22b(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction22b(bytecode, index, nullptr) {
}

Instruction22b::Instruction22b(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION22B, 4) {
    op = op_codes[0];
    vAA = op_codes[1];
    vBB = op_codes[2];
    nCC = static_cast<std::int8_t>(op_codes[3]);
}

std::uint8_t Instruction22b::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction22b::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction22b::get_first_operand() const {
    return vBB;
}

DexOpcodes::operand_type Instruction22b::get_first_operand_type() const {
    return DexOpcodes::REGISTER;
}

std::int8_t Instruction22b::get_second_operand() const {
    return nCC;
}

DexOpcodes::operand_type Instruction22b::get_second_operand_type() const {
    return DexOpcodes::LITERAL;
}

std::string_view Instruction22b::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vAA);
        instruction_str += ", v" + std::to_string(vBB);
        instruction_str += ", " + std::to_string(nCC);
    }
    return instruction_str;
}

void Instruction22b::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction22t::Instruction22t(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction22t(bytecode, index, nullptr) {
}

Instruction22t::Instruction22t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION22T, 4) {
    op = op_codes[0];
    vA = op_codes[1] & 0x0F;
    vB = (op_codes[1] & 0xF0) >> 4;
    nCCCC = *(reinterpret_cast<std::int16_t *>(&op_codes[2]));

    if (nCCCC == 0)
        throw exceptions::InvalidInstructionException("Error reading Instruction22t offset cannot be 0", 4);
}

std::uint8_t Instruction22t::get_first_operand() const {
    return vA;
}

DexOpcodes::operand_type Instruction22t::get_first_operand_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction22t::get_second_operand() const {
    return vB;
}

DexOpcodes::operand_type Instruction22t::get_second_operand_type() const {
    return DexOpcodes::REGISTER;
}

std::int16_t Instruction22t::get_offset() const {
    return nCCCC;
}

DexOpcodes::operand_type Instruction22t::get_offset_type() const {
    return DexOpcodes::OFFSET;
}

std::string_view Instruction22t::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vA);
        instruction_str += ", v" + std::to_string(vB);
        instruction_str += ", " + std::to_string(nCCCC);
    }
    return instruction_str;
}

void Instruction22t::print_instruction(std::ostream &os) {
    os << print_instruction();
}


Instruction22s::Instruction22s(std::span<uint8_t> bytecode, std::size_t index)
 : Instruction22s(bytecode, index, nullptr) {
}

Instruction22s::Instruction22s(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION22S, 4) {
    op = op_codes[0];
    vA = op_codes[1] & 0x0F;
    vB = (op_codes[1] & 0xF0) >> 4;
    nCCCC = *(reinterpret_cast<std::int16_t *>(&op_codes[2]));
}

std::uint8_t Instruction22s::get_destination() const {
    return vA;
}

DexOpcodes::operand_type Instruction22s::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction22s::get_first_operand() const {
    return vB;
}

DexOpcodes::operand_type Instruction22s::get_first_operand_type() const {
    return DexOpcodes::REGISTER;
}

std::int16_t Instruction22s::get_second_operand() const {
    return nCCCC;
}

DexOpcodes::operand_type Instruction22s::get_second_operand_type() const {
    return DexOpcodes::LITERAL;
}

std::string_view Instruction22s::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vA);
        instruction_str += ", v" + std::to_string(vB);
        instruction_str += ", " + std::to_string(nCCCC);
    }
    return instruction_str;
}

void Instruction22s::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction22c::Instruction22c(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction22c(bytecode, index, nullptr) {
}

Instruction22c::Instruction22c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION22C, 4) {
    op = op_codes[0];
    vA = op_codes[1] & 0x0F;
    vB = (op_codes[1] & 0xF0) >> 4;
    iCCCC = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    checked_id = std::monostate{};
    if (parser == nullptr) return;

    switch (get_kind()) {
        case shuriken::dex::TYPES::TYPE:
            checked_id = parser->get_types().get_type_by_id(iCCCC);
            break;
        case shuriken::dex::TYPES::FIELD:
            checked_id = parser->get_fields().get_field_by_id(iCCCC);
            break;
    }
}

std::uint8_t Instruction22c::get_destination() const {
    return vA;
}

DexOpcodes::operand_type Instruction22c::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint8_t Instruction22c::get_operand() const {
    return vB;
}

DexOpcodes::operand_type Instruction22c::get_operand_type() const {
    return DexOpcodes::REGISTER;
}

std::uint16_t Instruction22c::get_checked_id() const {
    return iCCCC;
}

DexOpcodes::operand_type Instruction22c::get_checked_id_type() const {
    return DexOpcodes::KIND;
}

shuriken::dex::TYPES::kind Instruction22c::get_checked_id_kind() const {
    return get_kind();
}

kind_type_t Instruction22c::get_checked_id_as_kind() const {
    return checked_id;
}

std::string_view Instruction22c::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vA);
        instruction_str += ", ";
        instruction_str += "v" + std::to_string(vB);
        instruction_str += ", ";
        instruction_str += get_kind_type_as_string(checked_id, iCCCC);
    }
    return instruction_str;
}

void Instruction22c::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction22cs::Instruction22cs(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction22cs(bytecode, index, nullptr) {
}

Instruction22cs::Instruction22cs(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION22CS, 4) {
    op = op_codes[0];
    vA = op_codes[1] & 0x0F;
    vB = (op_codes[1] & 0xF0) >> 4;
    iCCCC = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    field = std::monostate{};
    if (parser == nullptr) return;

    switch (get_kind()) {
        case shuriken::dex::TYPES::kind::FIELD:
            field = parser->get_fields().get_field_by_id(iCCCC);
            break;
    }
}

std::uint8_t Instruction22cs::get_dest_source_register() const {
    return vA;
}

DexOpcodes::operand_type Instruction22cs::get_dest_source_register_type() const {
    return DexOpcodes::operand_type::REGISTER;
}

std::uint8_t Instruction22cs::get_register_object() const {
    return vB;
}

DexOpcodes::operand_type Instruction22cs::get_register_object_type() const {
    return DexOpcodes::operand_type::REGISTER;
}

std::uint16_t Instruction22cs::get_field_offset() const {
    return iCCCC;
}

DexOpcodes::operand_type Instruction22cs::get_field_offset_type() const {
    return DexOpcodes::operand_type::KIND;
}

shuriken::dex::TYPES::kind Instruction22cs::get_field_kind() {
    return get_kind();
}

kind_type_t Instruction22cs::get_field() const {
    return field;
}

std::string_view Instruction22cs::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " ";
        instruction_str += "v" + std::to_string(vA);
        instruction_str += ", ";
        instruction_str += "v" + std::to_string(vB);
        instruction_str += ", ";
        instruction_str += get_kind_type_as_string(field, iCCCC);
    }
    return instruction_str;
}

void Instruction22cs::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction30t::Instruction30t(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction30t(bytecode, index, nullptr) {
}

Instruction30t::Instruction30t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION30T, 6) {
    if (op_codes[1] != 0)
        throw exceptions::InvalidInstructionException("Error reading Instruction30t padding must be 0", 6);

    op = op_codes[0];
    nAAAAAAAA = *(reinterpret_cast<std::int32_t *>(&op_codes[2]));

    if (nAAAAAAAA == 0)
        throw exceptions::InvalidInstructionException("Error reading Instruction30t offset cannot be 0", 6);
}

std::int32_t Instruction30t::get_offset() const {
    return nAAAAAAAA;
}

DexOpcodes::operand_type Instruction30t::get_offset_type() const {
    return DexOpcodes::operand_type::OFFSET;
}

std::string_view Instruction30t::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += std::to_string((nAAAAAAAA*2) + static_cast<std::int64_t>(address));
    }
    return instruction_str;
}

void Instruction30t::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction32x::Instruction32x(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction32x(bytecode, index, nullptr) {
}

Instruction32x::Instruction32x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION32X, 6) {
    if (op_codes[1] != 0)
        throw exceptions::InvalidInstructionException("Error reading Instruction32x padding must be 0", 6);

    op = op_codes[0];
    vAAAA = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    vBBBB = *(reinterpret_cast<std::uint16_t *>(&op_codes[4]));
}

std::uint16_t Instruction32x::get_destination() const {
    return vAAAA;
}

DexOpcodes::operand_type Instruction32x::get_destination_type() const {
    return DexOpcodes::operand_type::REGISTER;
}

std::uint16_t Instruction32x::get_source() const {
    return vBBBB;
}

DexOpcodes::operand_type Instruction32x::get_source_type() const {
    return DexOpcodes::operand_type::REGISTER;
}

std::string_view Instruction32x::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " v" + std::to_string(vAAAA);
        instruction_str += ", v" + std::to_string(vBBBB);
    }
    return instruction_str;
}

void Instruction32x::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction31i::Instruction31i(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction31i(bytecode, index, nullptr) {
}

Instruction31i::Instruction31i(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION31I, 6) {
    op = op_codes[0];
    vAA = op_codes[1];
    nBBBBBBBB = *(reinterpret_cast<std::uint32_t *>(&op_codes[2]));
}

std::uint8_t Instruction31i::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction31i::get_destination_type() const {
    return DexOpcodes::operand_type::REGISTER;
}

std::uint32_t Instruction31i::get_source() const {
    return nBBBBBBBB;
}

float Instruction31i::get_source_float() const {
    union
    {
        float f;
        std::uint32_t i;
    } conv;

    conv.i = nBBBBBBBB;

    return conv.f;
}

DexOpcodes::operand_type Instruction31i::get_source_type() const {
    return DexOpcodes::operand_type::LITERAL;
}

std::string_view Instruction31i::print_instruction() {
    if (instruction_str.empty()) {
        union
        {
            float f;
            std::uint32_t i;
        } conv;

        conv.i = nBBBBBBBB;

        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " v" + std::to_string(vAA);
        instruction_str += ", " + std::to_string(conv.f) + " // " + std::to_string(nBBBBBBBB);
    }
    return instruction_str;
}

void Instruction31i::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction31t::Instruction31t(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction31t(bytecode, index, nullptr) {
}

Instruction31t::Instruction31t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION31T, 6) {
    op = op_codes[0];
    vAA = op_codes[1];
    nBBBBBBBB = *(reinterpret_cast<std::int32_t *>(&op_codes[2]));
    switch_instruction = std::monostate{};

    switch (static_cast<DexOpcodes::opcodes>(op))
    {
        case DexOpcodes::opcodes::OP_PACKED_SWITCH:
            type_of_switch = PACKED_SWITCH;
            break;
        case DexOpcodes::opcodes::OP_SPARSE_SWITCH:
            type_of_switch = SPARSE_SWITCH;
            break;
        default:
            type_of_switch = NONE_SWITCH;
            break;
    }
}

std::uint8_t Instruction31t::get_ref_register() const {
    return vAA;
}

DexOpcodes::operand_type Instruction31t::get_ref_register_type() const {
    return DexOpcodes::REGISTER;
}

std::int32_t Instruction31t::get_offset() const {
    return nBBBBBBBB;
}

DexOpcodes::operand_type Instruction31t::get_offset_type() const {
    return DexOpcodes::OFFSET;
}

type_of_switch_t Instruction31t::get_type_of_switch() const {
    return type_of_switch;
}

switch_type_t Instruction31t::get_switch() const {
    return switch_instruction;
}

void Instruction31t::set_packed_switch(PackedSwitch* packed_switch) {
    this->switch_instruction = packed_switch;
}

void Instruction31t::set_sparse_switch(SparseSwitch *sparse_switch) {
    this->switch_instruction = sparse_switch;
}

std::string_view Instruction31t::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " v" + std::to_string(vAA);
        instruction_str += ", " + std::to_string(nBBBBBBBB);
    }
    return instruction_str;
}

void Instruction31t::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction31c::Instruction31c(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction31c(bytecode, index, nullptr) {
}

Instruction31c::Instruction31c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION31C, 6) {
    op = op_codes[0];
    vAA = op_codes[1];
    iBBBBBBBB = *(reinterpret_cast<std::uint32_t *>(&op_codes[2]));
    if (parser)
        string_value = parser->get_strings().get_string_by_id(iBBBBBBBB);
}

std::uint8_t Instruction31c::get_destination() const {
    return vAA;
}

DexOpcodes::operand_type Instruction31c::get_destination_type() const {
    return DexOpcodes::REGISTER;
}

std::uint32_t Instruction31c::get_string_idx() const {
    return iBBBBBBBB;
}

DexOpcodes::operand_type Instruction31c::get_string_idx_type() const {
    return DexOpcodes::OFFSET;
}

std::string_view Instruction31c::get_string_value() const {
    return string_value;
}

std::string_view Instruction31c::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " v" + std::to_string(vAA);
        instruction_str += ", " + std::to_string(iBBBBBBBB);
        if (!string_value.empty()) {
            instruction_str += " //";
            instruction_str += string_value;
        }
    }
    return instruction_str;
}

void Instruction31c::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction35c::Instruction35c(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction35c(bytecode, index, nullptr) {
}

Instruction35c::Instruction35c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION35C, 6) {
    /// for reading the registers
    std::uint8_t reg[5];

    op = op_codes[0];
    array_size = (op_codes[1] & 0xF0) >> 4;
    type_index = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    type_value = std::monostate{};

    /// assign the values to the registers
    reg[4] = op_codes[1] & 0x0F;
    reg[0] = op_codes[4] & 0x0F;
    reg[1] = (op_codes[4] & 0xF0) >> 4;
    reg[2] = op_codes[5] & 0x0F;
    reg[3] = (op_codes[5] & 0xF0) >> 4;

    if (array_size > 5)
        throw exceptions::InvalidInstructionException("Error in array size of Instruction35c, cannot be greater than 5", 6);

    for (size_t I = 0; I < array_size; ++I)
        registers.push_back(reg[I]);

    switch (get_kind()) {
        case shuriken::dex::TYPES::kind::TYPE:
            type_value = parser->get_types().get_type_by_id(type_index);
            break;
        case shuriken::dex::TYPES::kind::METH:
            type_value = parser->get_methods().get_method_by_id(type_index);
            break;
    }
}

std::uint8_t Instruction35c::get_number_of_registers() const {
    return array_size;
}

std::span<std::uint8_t> Instruction35c::get_registers() {
    std::span regs {registers};
    return regs;
}

DexOpcodes::operand_type Instruction35c::get_registers_type() {
    return DexOpcodes::REGISTER;
}

std::uint16_t Instruction35c::get_type_idx() const {
    return type_index;
}

DexOpcodes::operand_type Instruction35c::get_array_type() const {
    return DexOpcodes::KIND;
}

shuriken::dex::TYPES::kind Instruction35c::get_array_kind() const {
    return get_kind();
}

kind_type_t Instruction35c::get_array_value() const {
    return type_value;
}

std::string_view Instruction35c::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " {";
        for (auto reg : registers)
            instruction_str += "v" + std::to_string(reg) + ", ";
        if (!registers.empty())
            instruction_str = instruction_str.substr(0, instruction_str.size()-2);
        instruction_str += "}, " + get_kind_type_as_string(type_value, type_index);
    }
    return instruction_str;
}

void Instruction35c::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction3rc::Instruction3rc(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction3rc(bytecode, index, nullptr) {
}

Instruction3rc::Instruction3rc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION3RC, 6) {
    std::uint16_t vCCCC;
    op = op_codes[0];
    array_size = op_codes[1];
    index = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    vCCCC = *(reinterpret_cast<std::uint16_t *>(&op_codes[4]));
    index_value = std::monostate{};

    for (std::uint16_t I = vCCCC, E = vCCCC + array_size; I < E; I++)
        registers.push_back(I);

    if (parser == nullptr) return;

    switch (get_kind()) {
        case shuriken::dex::TYPES::TYPE:
            index_value = parser->get_types().get_type_by_id(index);
            break;
        case shuriken::dex::TYPES::METH:
            index_value = parser->get_methods().get_method_by_id(index);
            break;
    }
}

std::uint8_t Instruction3rc::get_registers_size() const {
    return array_size;
}

std::uint16_t Instruction3rc::get_index() const {
    return index;
}

kind_type_t Instruction3rc::get_index_value() const {
    return index_value;
}

DexOpcodes::operand_type Instruction3rc::get_index_type() const {
    return DexOpcodes::KIND;
}

shuriken::dex::TYPES::kind Instruction3rc::get_array_kind() const {
    return get_kind();
}

std::span<std::uint16_t> Instruction3rc::get_registers() {
    std::span<std::uint16_t > regs{registers};
    return regs;
}

std::string_view Instruction3rc::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " {";
        for (auto reg: registers)
            instruction_str += "v" + std::to_string(reg) + ", ";
        if (!registers.empty())
            instruction_str = instruction_str.substr(0, instruction_str.size() - 2);
        instruction_str += "}, " + get_kind_type_as_string(index_value, index);
    }
    return instruction_str;
}

void Instruction3rc::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction45cc::Instruction45cc(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction45cc(bytecode, index, nullptr) {
}

Instruction45cc::Instruction45cc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION45CC, 8) {
    std::uint8_t regC, regD, regE, regF, regG;

    op = op_codes[0];
    reg_count = (op_codes[1] & 0xF0) >> 4;
    regG = op_codes[1] & 0x0F;
    method_reference = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    regD = (op_codes[4] & 0xF0) >> 4;
    regC = op_codes[4] & 0x0F;
    regF = (op_codes[5] & 0xF0) >> 4;
    regE = op_codes[5] & 0x0F;
    prototype_reference = *(reinterpret_cast<std::uint16_t *>(&op_codes[8]));
    method_value = std::monostate{};
    prototype_value = std::monostate{};

    if (reg_count > 5)
        throw exceptions::InvalidInstructionException("Error in reg_count from Instruction45cc cannot be greater than 5", 8);

    if (reg_count > 0)
        registers.push_back(regC);
    if (reg_count > 1)
        registers.push_back(regD);
    if (reg_count > 2)
        registers.push_back(regE);
    if (reg_count > 3)
        registers.push_back(regF);
    if (reg_count > 4)
        registers.push_back(regG);

    if (parser == nullptr) return;

    if (method_reference >= parser->get_methods().get_number_of_methods())
        throw exceptions::InvalidInstructionException("Error method reference out of bound in Instruction45cc", 8);

    if (prototype_reference >= parser->get_protos().get_number_of_protos())
        throw exceptions::InvalidInstructionException("Error prototype reference out of bound in Instruction45cc", 8);

    method_value = parser->get_methods().get_method_by_id(method_reference);
    prototype_value = parser->get_protos().get_proto_by_id(prototype_reference);
}

std::uint8_t Instruction45cc::get_number_of_registers() const {
    return reg_count;
}

std::span<std::uint8_t> Instruction45cc::get_registers() {
    std::span<std::uint8_t> reg{registers};
    return reg;
}

std::uint16_t Instruction45cc::get_method_reference() const {
    return method_reference;
}

kind_type_t Instruction45cc::get_method_value() const {
    return method_value;
}

std::uint16_t Instruction45cc::get_prototype_reference() const {
    return prototype_reference;
}

kind_type_t Instruction45cc::get_prototype_value() const {
    return prototype_value;
}

std::string_view Instruction45cc::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str = " {";
        for(const auto reg : registers)
            instruction_str += "v" + std::to_string(reg) + ", ";
        if (!registers.empty())
            instruction_str = instruction_str.substr(0, instruction_str.size()-2);
        instruction_str += "}, ";
        instruction_str += "meth@" + std::to_string(method_reference) + ", ";
        instruction_str += "proto@" + std::to_string(prototype_reference);
    }
    return instruction_str;
}

void Instruction45cc::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction4rcc::Instruction4rcc(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction4rcc(bytecode, index, nullptr) {
}

Instruction4rcc::Instruction4rcc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION4RCC, 8) {
    std::uint16_t vCCCC;

    op = op_codes[0];
    reg_count = op_codes[1];
    method_reference = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    vCCCC = *(reinterpret_cast<std::uint16_t *>(&op_codes[4]));
    prototype_reference = *(reinterpret_cast<std::uint16_t *>(&op_codes[6]));
    method_value = std::monostate{};
    prototype_value = std::monostate{};

    for (std::uint16_t I = vCCCC, E = vCCCC + reg_count; I < E; ++I)
        registers.push_back(I);

    if (parser == nullptr) return;

    if (method_reference >= parser->get_methods().get_number_of_methods())
        throw exceptions::InvalidInstructionException("Error method reference out of bound in Instruction4rcc", 8);

    if (prototype_reference >= parser->get_protos().get_number_of_protos())
        throw exceptions::InvalidInstructionException("Error prototype reference out of bound in Instruction4rcc", 8);

    method_value = parser->get_methods().get_method_by_id(method_reference);
    prototype_value = parser->get_protos().get_proto_by_id(prototype_reference);
}

std::uint8_t Instruction4rcc::get_number_of_registers() const {
    return reg_count;
}

std::span<std::uint16_t> Instruction4rcc::get_registers() {
    std::span<std::uint16_t> reg{registers};
    return reg;
}

std::uint16_t Instruction4rcc::get_method_reference() const {
    return method_reference;
}

kind_type_t Instruction4rcc::get_method_value() const {
    return method_value;
}

std::uint16_t Instruction4rcc::get_prototype_reference() const {
    return prototype_reference;
}

kind_type_t Instruction4rcc::get_prototype_value() const {
    return prototype_value;
}

std::string_view Instruction4rcc::print_instruction() {
    if (instruction_str.empty()) {
        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str = " {";
        for(const auto reg : registers)
            instruction_str += "v" + std::to_string(reg) + ", ";
        if (!registers.empty())
            instruction_str = instruction_str.substr(0, instruction_str.size()-2);
        instruction_str += "}, ";
        instruction_str += "meth@" + std::to_string(method_reference) + ", ";
        instruction_str += "proto@" + std::to_string(prototype_reference);
    }
    return instruction_str;
}

void Instruction4rcc::print_instruction(std::ostream &os) {
    os << print_instruction();
}

Instruction51l::Instruction51l(std::span<uint8_t> bytecode, std::size_t index)
    : Instruction51l(bytecode, index, nullptr) {
}

Instruction51l::Instruction51l(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_INSTRUCTION51L, 10) {
    op = op_codes[0];
    vAA = op_codes[1];
    nBBBBBBBBBBBBBBBB = *(reinterpret_cast<std::int64_t *>(&op_codes[2]));
}

std::uint8_t Instruction51l::get_first_register() const {
    return vAA;
}

DexOpcodes::operand_type Instruction51l::get_first_register_type() const {
    return DexOpcodes::REGISTER;
}

std::int64_t Instruction51l::get_wide_value() const {
    return nBBBBBBBBBBBBBBBB;
}

double Instruction51l::get_wide_value_as_double() const {
    union
    {
        double d;
        std::uint64_t j;
    } conv;

    conv.j = nBBBBBBBBBBBBBBBB;

    return conv.d;
}

DexOpcodes::operand_type Instruction51l::get_wide_value_type() const {
    return DexOpcodes::LITERAL;
}

std::string_view Instruction51l::print_instruction() {
    if (instruction_str.empty()) {
        /// https://android.googlesource.com/platform/art/+/master/dexdump/dexdump.cc#1212
        union
        {
            double d;
            std::uint64_t j;
        } conv;

        conv.j = nBBBBBBBBBBBBBBBB;

        instruction_str = opcode_names.at(static_cast<DexOpcodes::opcodes>(op));
        instruction_str += " v" + std::to_string(vAA);
        instruction_str += ", #" + std::to_string(conv.d);
        instruction_str += " // " + std::to_string(nBBBBBBBBBBBBBBBB);
    }
    return instruction_str;
}

void Instruction51l::print_instruction(std::ostream &os) {
    os << print_instruction();
}

PackedSwitch::PackedSwitch(std::span<uint8_t> bytecode, std::size_t index)
    : PackedSwitch(bytecode, index, nullptr) {
}

PackedSwitch::PackedSwitch(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_PACKEDSWITCH, 8) {
    std::int32_t aux;

    op = *(reinterpret_cast<std::uint16_t *>(&op_codes[0]));
    size = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    first_key = *(reinterpret_cast<std::int32_t *>(&op_codes[4]));

    // because the instruction is larger, we have to
    // re-accomodate the op_codes span and the length
    // we have to increment it
    length += (size * 4);

    op_codes = {bytecode.begin() + index, bytecode.begin() + index + length};

    // now read the targets
    auto multiplier = sizeof(std::int32_t);
    for (size_t I = 0; I < size; ++I) {
        aux = *(reinterpret_cast<std::int32_t *>(&op_codes[8 + (I * multiplier)]));
        targets.push_back(aux);
    }
}

std::uint16_t PackedSwitch::get_number_of_targets() const {
    return size;
}

std::int32_t PackedSwitch::get_first_key() const {
    return first_key;
}

std::span<std::int32_t> PackedSwitch::get_targets() {
    std::span<std::int32_t> tgts{targets};
    return tgts;
}

std::string_view PackedSwitch::print_instruction() {
    if (instruction_str.empty()) {
        std::stringstream data;
        data << opcode_names.at(static_cast<DexOpcodes::opcodes>(op)) + " (size)" +
                  std::to_string(size) + " (first/last key)" + std::to_string(first_key) + "[";
        for (const auto target : targets)
            data << "0x" << std::hex << target << ",";
        if (size > 0)
            data.seekp(-1, data.cur);
        data << "]";
        instruction_str = data.str();
    }
    return instruction_str;
}

void PackedSwitch::print_instruction(std::ostream &os) {
    os << print_instruction();
}

SparseSwitch::SparseSwitch(std::span<uint8_t> bytecode, std::size_t index)
    : SparseSwitch(bytecode, index, nullptr) {
}

SparseSwitch::SparseSwitch(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_SPARSESWITCH, 4) {
    std::int32_t aux_key, aux_target;

    op = *(reinterpret_cast<std::uint16_t *>(&op_codes[0]));
    size = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));

    // now we have to do as before, we have to set the appropiate
    // length and also fix the span object
    // the length is the number of keys and targets multiplied by
    // the size of each one
    length += (sizeof(std::int32_t) * size) * 2;
    op_codes = {bytecode.begin() + index, bytecode.begin() + index + length};

    auto base_targets = 4 + sizeof(std::int32_t) * size;
    auto multiplier = sizeof(std::int32_t);

    for (size_t I = 0; I < size; ++I) {
        aux_key = *(reinterpret_cast<std::int32_t *>(&op_codes[4 + I * multiplier]));
        aux_target = *(reinterpret_cast<std::int32_t *>(&op_codes[base_targets + I * multiplier]));

        keys_targets.emplace_back(aux_key, aux_target);
    }
}

std::uint16_t SparseSwitch::get_size_of_targets() const {
    return size;
}

std::span<std::pair<std::int32_t, std::int32_t>> SparseSwitch::get_keys_targets() {
    return keys_targets;
}

std::string_view SparseSwitch::print_instruction() {
    if (instruction_str.empty()) {
        std::stringstream output;
        output << opcode_names.at(static_cast<DexOpcodes::opcodes>(op)) << " (size)" << size << "[";
        for (const auto& key_target : keys_targets) {
            auto key = std::get<0>(key_target);
            auto target = std::get<1>(key_target);
            if (key < 0)
                output << "-0x" << std::hex << key << ":";
            else
                output << "0x" << std::hex << key << ":";
            if (target < 0)
                output << "-0x" << std::hex << target << ":";
            else
                output << "0x" << std::hex << target << ":";
            output << ",";
        }
        if (size > 0)
            output.seekp(-1, std::stringstream::cur);
        output << "]";
        instruction_str = output.str();
    }
    return instruction_str;
}

void SparseSwitch::print_instruction(std::ostream &os) {
    os << print_instruction();
}


FillArrayData::FillArrayData(std::span<uint8_t> bytecode, std::size_t index)
    : FillArrayData(bytecode, index, nullptr) {
}

FillArrayData::FillArrayData(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser * parser)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_FILLARRAYDATA, 8) {
    std::uint8_t aux;

    op = *(reinterpret_cast<std::uint16_t *>(&op_codes[0]));
    element_width = *(reinterpret_cast<std::uint16_t *>(&op_codes[2]));
    size = *(reinterpret_cast<std::uint32_t *>(&op_codes[4]));

    // again we have to fix the length of the instruction
    // and also the opcodes
    auto buff_size = (size * element_width);
    length += buff_size;
    if (buff_size % 2 != 0)
        length += 1;
    op_codes = {bytecode.begin() + index, bytecode.begin() + index + length};

    for (size_t I = 0; I < buff_size; ++I)
        data.push_back(op_codes[8 + I]);
}

std::uint16_t FillArrayData::get_element_width() const {
    return element_width;
}

std::uint32_t FillArrayData::get_size_of_data() const {
    return size;
}

std::span<std::uint8_t> FillArrayData::get_data() {
    std::span<std::uint8_t> dat{data};
    return data;
}

std::string_view FillArrayData::print_instruction() {
    if (instruction_str.empty()) {
        std::stringstream output;
        output << "(width)" << element_width << " (size)" << size << " [";
        for (auto byte : data)
            output << "0x" << std::hex << static_cast<std::uint32_t>(byte) << ",";
        if (size > 0)
            output.seekp(-1, std::stringstream::cur);
        output << "]";
        instruction_str = output.str();
    }
    return instruction_str;
}

void FillArrayData::print_instruction(std::ostream &os) {
    os << print_instruction();
}

DalvikIncorrectInstruction::DalvikIncorrectInstruction(std::span<uint8_t> bytecode, std::size_t index, std::uint32_t length)
    : Instruction(bytecode, index, DexOpcodes::dexinsttype::DEX_DALVIKINCORRECT, length) {
}

std::string_view DalvikIncorrectInstruction::print_instruction() {
    if (instruction_str.empty()) {
        std::stringstream stream;
        stream << "DalvikInvalidInstruction [length: " << length << "][Opcodes: ";
        for (const auto val : op_codes)
            stream << std::hex << val << " ";
        stream.seekp(-1, std::stringstream::cur);
        stream << "]";
        instruction_str = stream.str();
    }
    return instruction_str;
}

void DalvikIncorrectInstruction::print_instruction(std::ostream &os) {
    os << print_instruction();
}