//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_instructions.h
// @brief Classes that represent the instructions in the dalvik virtual machine

#ifndef SHURIKENLIB_DALVIK_INSTRUCTIONS_H
#define SHURIKENLIB_DALVIK_INSTRUCTIONS_H

#include "shuriken/common/Dex/dvm_types.h"
#include "shuriken/disassembler/Dex/dex_opcodes.h"
#include "shuriken/parser/Dex/parser.h"

#include <iostream>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace shuriken::disassembler::dex {

    /// @brief Some instructions depending on the kind of the instruction
    /// will make use of a type with different possible values.
    using kind_type_t = std::variant<
            std::monostate,
            shuriken::parser::dex::DVMType *,
            shuriken::parser::dex::FieldID *,
            shuriken::parser::dex::MethodID *,
            shuriken::parser::dex::ProtoID *,
            std::string_view>;


    /// Forward declaration of different type of switch
    class PackedSwitch;
    class SparseSwitch;

    using switch_type_t = std::variant<
            std::monostate,
            PackedSwitch *,
            SparseSwitch *>;

    /// @brief Enum specifying the type of switch
    /// for the data table
    enum type_of_switch_t {
        PACKED_SWITCH = 0,
        SPARSE_SWITCH,
        NONE_SWITCH
    };

    /// Declaration for using it in InstructionUtils
    class Instruction;

    class InstructionUtils {
    public:
        /// @brief Get the operation type from the given opcode
        /// @return operation type
        static DexOpcodes::operation_type get_operation_type_from_opcode(DexOpcodes::opcodes opcode);

        /// @brief Get operation type from a given instruction
        /// @param instr instruction to retrieve the operation type
        /// @return operation type
        static DexOpcodes::operation_type get_operation_type_from_instruction(Instruction *instr);

        /// @return if operation type is a jump of any type unconditional, conditional, switch
        static bool is_jump_instruction(Instruction *instr);
    };

    /// @brief Base type for all the instructions
    /// it implements all of the virtual functions
    /// and it contains the basic variables all instructions
    /// should have
    class Instruction {
    private:
        /// @brief Instruction type from the enum
        DexOpcodes::dexinsttype instruction_type;

    protected:
        /// @brief Opcodes of the instruction
        std::span<std::uint8_t> op_codes;
        /// @brief Length of the instruction
        std::uint32_t length;
        /// @brief op code from the instruction
        std::uint32_t op;
        /// @brief address of the instruction
        std::uint64_t address = 0;
        /// @brief string representation of the instruction
        std::string instruction_str;

    public:
        /// @brief Constructor of the Instruction, here is applied
        /// the parsing of the opcodes
        /// @param bytecode bytes of the instruction
        /// @param index index of the instruction in the buffer of bytes
        /// @param instruction_type type of instruction
        Instruction(std::span<uint8_t> bytecode, std::size_t index, DexOpcodes::dexinsttype instruction_type);

        /// @brief Constructor of the Instruction, here is applied
        /// the parsing of the opcodes
        /// @param bytecode bytes of the instruction
        /// @param index index of the instruction in the buffer of bytes
        /// @param instruction_type type of instruction
        /// @param length length of the instruction in bytes
        Instruction(std::span<uint8_t> bytecode, std::size_t index, DexOpcodes::dexinsttype instruction_type, std::uint32_t length);

        /// @brief Destructor of the instruction
        virtual ~Instruction() = default;

        /// @brief Get the kind of instruction, use a DalvikOpcodes function
        /// @return TYPES::Kind of the instruction
        virtual shuriken::dex::TYPES::kind get_kind() const;

        /// @brief Get the instruction type from the enum
        /// @return dex instruction type
        virtual DexOpcodes::dexinsttype get_instruction_type() const;

        /// @brief Get the length of the instruction
        /// @return current length of the instruction
        virtual std::uint32_t get_instruction_length() const;

        /// @brief Get the opcode of the instruction
        /// @return opcode of the instruction
        virtual std::uint32_t get_instruction_opcode() const;

        /// @brief Set the address of the instruction
        /// @param address new address of the instruction
        virtual void set_address(std::uint64_t new_address);

        /// @brief Get the address of the instruction
        /// @return address of the instruction
        virtual std::uint64_t get_address() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        virtual std::string_view print_instruction() = 0;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        virtual void print_instruction(std::ostream &os) = 0;

        /// @brief Return the op codes in raw from the instruction
        /// @return copy of the span with the raw bytecode
        virtual std::span<std::uint8_t> get_opcodes();

        /// @brief Check if the instruction is a terminator (branch, ret, multibranch)
        /// @return true if instruction is a terminator instruction
        virtual bool is_terminator();

        /// @brief Instruction has or can have some side effect.
        /// @return boolean indicating if a side effect exists
        virtual bool has_side_effects() const;

        /// @brief May throw an exception
        /// @return boolean indicating if instruction can throw an exception
        virtual bool may_throw() const;
    };

    /// @brief Useless instruction with opcode of 00
    /// no instruction represents this, it's not either a nop
    class Instruction00x : public Instruction {
    public:
        Instruction00x(std::span<uint8_t> bytecode, std::size_t index);

        /// @brief Constructor of Instruction00x this instruction does nothing
        /// @param bytecode bytecode with the opcodes
        /// @param index
        Instruction00x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Instruction for wasting cycles. It represents
    /// a nop, it has a length of 2
    class Instruction10x : public Instruction {
    public:
        Instruction10x(std::span<uint8_t> bytecode, std::size_t index);

        Instruction10x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move the contents of one register to another
    /// length of the instruction is 2 bytes, it contains
    /// two registers vA and vB of 4 bits each one
    class Instruction12x : public Instruction {
    private:
        /// @brief destination register
        std::uint8_t vA;
        /// @brief source register
        std::uint8_t vB;

    public:
        Instruction12x(std::span<uint8_t> bytecode, std::size_t index);

        Instruction12x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the destination register
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the operand type of the destination
        /// @return operand type of destination
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the index of the source register
        /// @return index of source register
        std::uint8_t get_source() const;

        /// @brief Get the operand type of the source
        /// @return operand type of source
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Instruction for moving a given literal, the
    /// instruction has a register and a literal value, with
    /// a size of 2 bytes of instruction
    class Instruction11n : public Instruction {
    private:
        /// @brief destination register
        std::uint8_t vA;
        /// @brief Literal value of instruction
        std::int8_t nB;

    public:
        Instruction11n(std::span<uint8_t> bytecode, std::size_t index);

        Instruction11n(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the destination register
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the operand type of the destination
        /// @return operand type of destination
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the source value
        /// @return source value
        std::int8_t get_source() const;

        /// @brief Get the operand type of the source
        /// @return operand type of source
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move single, double-words or objects from
    /// invoke results, also save caught exception into
    /// given register
    class Instruction11x : public Instruction {
    private:
        /// @brief  destination of move
        std::uint8_t vAA;

    public:
        Instruction11x(std::span<uint8_t> bytecode, std::size_t index);

        Instruction11x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get destination register index of the operation
        /// @return index of register
        std::uint8_t get_destination() const;

        /// @brief Get the type of operand for the destination
        /// @return operand type of register
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Unconditional jump instruction. An offset
    /// is given to know where to jump
    class Instruction10t : public Instruction {
    private:
        /// @brief Offset where to jump with unconditional jump
        std::int8_t nAA;

    public:
        Instruction10t(std::span<uint8_t> bytecode, std::size_t index);

        Instruction10t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get offset of the jump
        /// @return offset of jump instruction
        std::int8_t get_offset() const;

        /// @brief Get type of operand in this case an offset
        /// @return return offset type
        DexOpcodes::operand_type get_operand_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Another unconditional jump with a bigger offset
    /// of 2 bytes for the offset
    class Instruction20t : public Instruction {
    private:
        /// @brief Offset where to jump
        std::int16_t nAAAA;

    public:
        Instruction20t(std::span<uint8_t> bytecode, std::size_t index);

        Instruction20t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the offset where to jump with an unconditional jump
        /// @return offset of the jump
        std::int16_t get_offset() const;

        /// @brief Get type of operand in this case an offset
        /// @return return offset type
        DexOpcodes::operand_type get_operand_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief opAA, kind@BBBB, where AA indicates a type of error
    /// and BBBB and index into the appropiate table
    class Instruction20bc : public Instruction {
    private:
        /// @brief type of error
        std::uint8_t nAA;
        /// @brief index into appropiate table
        std::uint16_t nBBBB;

    public:
        Instruction20bc(std::span<uint8_t> bytecode, std::size_t index);

        Instruction20bc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the type of error
        /// @return index of error
        std::uint8_t get_type_of_error_data() const;

        /// @brief Get the type of operand for the error operand
        /// @return literal type
        DexOpcodes::operand_type get_error_operand_type() const;

        /// @brief Get the index to the appropriate table of the instruction.
        /// @return index into a type-appropriate table (e.g. method references for
        /// no-such method error)
        std::uint16_t get_index_into_table() const;

        /// @brief Get the type of the index
        /// @return a KIND type
        DexOpcodes::operand_type get_index_operand_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move the contents of one non-object register to another.
    /// an instruction like move/from16 vAA, vBBBB where vAA is 8 bits,
    /// and vBBBB is 16 bits
    class Instruction22x : public Instruction {
    private:
        /// @brief destination register (8 bits)
        std::uint8_t vAA;
        /// @brief source register (16 bits)
        std::uint16_t vBBBB;

    public:
        Instruction22x(std::span<uint8_t> bytecode, std::size_t index);

        Instruction22x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get index of the register of destination
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the type of operand from the destination
        /// @return operand type of destination
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the index of the register of the source
        /// @return index of source register
        std::uint16_t get_source() const;

        /// @brief Get the type of operand from the source
        /// @return operand type of source
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Branch to the given destination if the given
    /// register's value compares with 0 as specified.
    /// Example: if-testz vAA, +BBBB where vAA is the register
    /// to test (8 bits) and +BBBB the offset (16 bits)
    class Instruction21t : public Instruction {
    private:
        /// @brief Register to check against zero
        std::uint8_t vAA;
        /// @brief Offset where to jump if-zero
        std::int16_t nBBBB;

    public:
        Instruction21t(std::span<uint8_t> bytecode, std::size_t index);

        Instruction21t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the register used for the check in the jump
        /// @return register checked
        std::uint8_t get_check_reg() const;

        /// @brief Get the type of the checked register
        /// @return type register
        DexOpcodes::operand_type get_check_reg_type() const;

        /// @brief Get the offset of the jump
        /// @return offset of jump
        std::int16_t get_jump_offset() const;

        /// @brief Get the type of the offset of the jump
        /// @return type of offset
        DexOpcodes::operand_type get_offset_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move given literal value into specified register.
    /// Example of instruction: const/16 vAA, #+BBBB. Where
    /// vAA is the destination register and #+BBBB is the literal
    /// moved
    class Instruction21s : public Instruction {
    private:
        /// @brief destination register
        std::uint8_t vAA;
        /// @brief literal value
        std::int16_t nBBBB;

    public:
        Instruction21s(std::span<uint8_t> bytecode, std::size_t index);

        Instruction21s(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the destination register
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the destination type of the instruction
        /// @return destination type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the source value of the instruction
        /// @return source value
        std::int16_t get_source() const;

        /// @brief Get the source type of the instruction
        /// @return source type
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move given literal value into specified register.
    /// Example: const/high16 vAA, #+BBBB0000 where vAA is the
    /// destination register (8 bits) and  #+BBBB0000: signed int (16 bits)
    class Instruction21h : public Instruction {
    private:
        /// @brief Destination register
        std::uint8_t vAA;
        /// @brief source value
        std::int64_t nBBBB;

    public:
        Instruction21h(std::span<uint8_t> bytecode, std::size_t index);

        Instruction21h(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the destination register
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the destination type of the instruction
        /// @return destination type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the source value of the instruction
        /// @return source value
        std::int64_t get_source() const;

        /// @brief Get the source type of the instruction
        /// @return source type
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move a reference to a register from a string, type, etc
    /// example instruction: const-string vAA, string@BBBB
    class Instruction21c : public Instruction {
    private:
        /// @brief destination register (8 bits)
        std::uint8_t vAA;
        /// @brief source id, this can be a string, type, etc (16 bits)
        std::uint16_t iBBBB;
        /// @brief Kind depending on the value
        kind_type_t source_id;

    public:
        Instruction21c(std::span<uint8_t> bytecode, std::size_t index);

        Instruction21c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the register for destination
        /// @return index of register
        std::uint8_t get_destination() const;

        /// @brief Get the type of the destination
        /// @return return register operand type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the index used as source operand,
        /// this is an index to a string, type, etc...
        /// @return value of index
        std::uint16_t get_source() const;

        /// @brief Get the type of the source, this time is a KIND
        /// the KIND can be various things
        /// @return return operation_type type
        DexOpcodes::operand_type get_source_type() const;

        /// @brief This function is a copy of get_kind but it will
        /// be used to ask for the kind of the source operand.
        /// @return return the kind of this operand.
        shuriken::dex::TYPES::kind get_source_kind() const;

        /// @brief Get the source as the std::variant of kind_type_t
        /// @return return source real value
        kind_type_t get_source_as_kind() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Perform indicated floating point or long comparison
    /// Example: cmpkind vAA, vBB, vCC
    class Instruction23x : public Instruction {
    private:
        /// @brief destination register (8 bits).
        std::uint8_t vAA;
        /// @brief first source register or pair (8 bits).
        std::uint8_t vBB;
        /// @brief second source register or pair (8 bits).
        std::uint8_t vCC;

    public:
        Instruction23x(std::span<uint8_t> bytecode, std::size_t index);

        Instruction23x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the register for the destination
        /// @return destination register
        std::uint8_t get_destination() const;

        /// @brief Get the type of the destination
        /// @return get REGISTER operand
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the register for the first source
        /// @return first source register
        std::uint8_t get_first_source() const;

        /// @brief Get the type of the first source
        /// @return get REGISTER operand
        DexOpcodes::operand_type get_first_source_type() const;

        /// @brief Get the register for the second source
        /// @return second source register
        std::uint8_t get_second_source() const;

        /// @brief Get the type of the second source
        /// @return get REGISTER operand
        DexOpcodes::operand_type get_second_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Perform indicated binary operation on the indicated
    /// register and literal value, storing result in destination
    /// register. Example: add-int/lit8 vAA, vBB, #+CC
    /// Semantic of the instruction: vAA = vBB + #+CC
    class Instruction22b : public Instruction {
    private:
        /// @brief Destination register (8 bits)
        std::uint8_t vAA;
        /// @brief First operand (8 bits)
        std::uint8_t vBB;
        /// @brief Second operand (8 bits)
        std::int8_t nCC;

    public:
        Instruction22b(std::span<uint8_t> bytecode, std::size_t index);

        Instruction22b(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index value of the destination register
        /// @return register index
        std::uint8_t get_destination() const;

        /// @brief Get the type of the destination
        /// @return return REGISTER type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the first operand of the instruction
        /// @return index of register operand
        std::uint8_t get_first_operand() const;

        /// @brief Get the type of the first operand
        /// @return return REGISTER type
        DexOpcodes::operand_type get_first_operand_type() const;

        /// @brief Get the value of the second operand
        /// @return value of second operand
        std::int8_t get_second_operand() const;

        /// @brief Get the type of the second operand
        /// @return return LITERAL type
        DexOpcodes::operand_type get_second_operand_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Branch to given offset after comparison of two registers.
    /// Example if-test vA, vB, +CCCC
    class Instruction22t : public Instruction {
    private:
        /// @brief First register checked (4 bits)
        std::uint8_t vA;
        /// @brief Second register checked (4 bits)
        std::uint8_t vB;
        /// @brief Offset where to jump
        std::int16_t nCCCC;

    public:
        Instruction22t(std::span<uint8_t> bytecode, std::size_t index);

        Instruction22t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the first operand of the check
        /// @return index of register
        std::uint8_t get_first_operand() const;

        /// @brief Get the type of the first operand of the comparison
        /// @return return REGISTER type
        DexOpcodes::operand_type get_first_operand_type() const;

        /// @brief Get the second operand of the check
        /// @return index of register
        std::uint8_t get_second_operand() const;

        /// @brief Get the type of the second operand of the comparison
        /// @return return REGISTER type
        DexOpcodes::operand_type get_second_operand_type() const;

        /// @brief Get the offset of the jump in case this is taken
        /// @return offset for the conditional jump
        std::int16_t get_offset() const;

        /// @brief Get the type of the offset for the jump
        /// @return return OFFSET type
        DexOpcodes::operand_type get_offset_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Perform indicated binary operation on the operands
    /// storing finally the result in the destination register.
    /// Example: add-int/lit16 vA, vB, #+CCCC
    /// Semantic: vA = vB + #+CCCC
    class Instruction22s : public Instruction {
    private:
        /// @brief destination regsiter (4 bits)
        std::uint8_t vA;
        /// @brief first operand (4 bits)
        std::uint8_t vB;
        /// @brief second operand (16 bits)
        std::int16_t nCCCC;

    public:
        Instruction22s(std::span<uint8_t> bytecode, std::size_t index);

        Instruction22s(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the destination of the operation
        /// @return index of the destination register
        std::uint8_t get_destination() const;

        /// @brief Get the type of the operand used for destination
        /// @return get REGISTER type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the first operand of the instruction
        /// @return index of register for operand
        std::uint8_t get_first_operand() const;

        /// @brief Get the type of the first operand of the instruction
        /// @return return REGISTER type
        DexOpcodes::operand_type get_first_operand_type() const;

        /// @brief Get the second operand of the instruction
        /// @return literal value used in the instruction
        std::int16_t get_second_operand() const;

        /// @brief Get the type of the second operand of the instruction
        /// @return return LITERAL type
        DexOpcodes::operand_type get_second_operand_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Store in the given destination 1 if the register
    /// provided contains an instance of the given type/field,
    /// 0 in other case.
    /// Example: instance-of vA, vB, type@CCCC
    /// Semantic: vA = type(vB) == type@CCCC ? 1 : 0
    class Instruction22c : public Instruction {
    private:
        /// @brief Destination register (4 bits)
        std::uint8_t vA;
        /// @brief Register with type to check (4 bits)
        std::uint8_t vB;
        /// @brief Type/FieldID to check
        std::uint16_t iCCCC;
        /// @brief last value as a kind type
        kind_type_t checked_id;

    public:
        Instruction22c(std::span<uint8_t> bytecode, std::size_t index);

        Instruction22c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the destination operand for the instruction
        /// @return index of the register for the destination
        std::uint8_t get_destination() const;

        /// @brief Get the destination operand type
        /// @return return REGISTER type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the operand checked in the instruction
        /// @return index of the register checked
        std::uint8_t get_operand() const;

        /// @brief Get the type of the operand of the instruction
        /// @return return REGISTER type
        DexOpcodes::operand_type get_operand_type() const;

        /// @brief Get the ID of the checked Type/Field
        /// @return ID of checked Type/Field
        std::uint16_t get_checked_id() const;

        /// @brief Get the type of the checked ID
        /// @return return KIND type
        DexOpcodes::operand_type get_checked_id_type() const;

        /// @brief Simply call the get_kind to know the kind of checked id
        /// @return kind of checked id
        shuriken::dex::TYPES::kind get_checked_id_kind() const;

        /// @brief Get the checked id as a correct type
        /// @return checked id
        kind_type_t get_checked_id_as_kind() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Format suggested for statically linked field access
    /// instructions or Types. Example: op vA, vB, fieldoff@CCCC
    /// *-QUICK methods
    class Instruction22cs : public Instruction {
    private:
        /// @brief Maybe destination?
        std::uint8_t vA;
        /// @brief Maybe where field is?
        std::uint8_t vB;
        /// @brief the field offset
        std::uint16_t iCCCC;
        /// @brief field value as a kind variable
        kind_type_t field;

    public:
        Instruction22cs(std::span<uint8_t> bytecode, std::size_t index);

        Instruction22cs(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the index of the first register used in the instruction
        /// @return value of register A it can be source or destination
        std::uint8_t get_dest_source_register() const;

        /// @brief Get the type for the register A
        /// @return return REGISTER type
        DexOpcodes::operand_type get_dest_source_register_type() const;

        /// @brief Get the index of the second register used in the instruction
        /// @return value of register B
        std::uint8_t get_register_object() const;

        /// @brief Get the type for the register B
        /// @return return REGISTER type
        DexOpcodes::operand_type get_register_object_type() const;

        /// @brief Get the offset for the field
        /// @return int value with field for offset
        std::uint16_t get_field_offset() const;

        /// @brief Get the type for the offset, probably KIND
        /// @return return KIND type (I think is that one...)
        DexOpcodes::operand_type get_field_offset_type() const;

        /// @brief A copy of get_kind just for the last operator
        /// @return Kind of the instruction
        shuriken::dex::TYPES::kind get_field_kind();

        /// @brief Get the field as a kind_type_t
        /// @return field operator
        kind_type_t get_field() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Unconditional jump to indicated offset
    /// Example: goto/32 +AAAAAAAA
    class Instruction30t : public Instruction {
    private:
        /// @brief offset where to jump in the instruction (32 bits)
        std::int32_t nAAAAAAAA;

    public:
        Instruction30t(std::span<uint8_t> bytecode, std::size_t index);

        Instruction30t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the offset of the jump
        /// @return offset of unconditional jump
        std::int32_t get_offset() const;

        /// @brief Get the type of the offset
        /// @return return OFFSET of the jump
        DexOpcodes::operand_type get_offset_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Binary operation between registers of 16 bits
    /// Example: move/16 vAAAA, vBBBB
    class Instruction32x : public Instruction {
    private:
        /// @brief Destination register (16 bits)
        std::uint16_t vAAAA;
        /// @brief Source register (16 bits)
        std::uint16_t vBBBB;

    public:
        Instruction32x(std::span<uint8_t> bytecode, std::size_t index);

        Instruction32x(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the destination operand of the instruction
        /// @return index of register destination
        std::uint16_t get_destination() const;

        /// @brief Get the type of the destination operand
        /// @return return REGISTER type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the source operand of the instruction
        /// @return index of register source
        std::uint16_t get_source() const;

        /// @brief Get the type of the source operand
        /// @return return REGISTER type
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Instructions between a register and
    /// a literal value of 32 bits.
    /// Example: const vAA, #+BBBBBBBB
    class Instruction31i : public Instruction {
    private:
        /// @brief destination register (8 bits)
        std::uint8_t vAA;
        /// @brief source value (32 bits)
        std::uint32_t nBBBBBBBB;

    public:
        Instruction31i(std::span<uint8_t> bytecode, std::size_t index);

        Instruction31i(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the destination operand of the instruction
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the destination operand type of the instruction
        /// @return return REGISTER type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the source operand of the instruction
        /// @return value of source operand
        std::uint32_t get_source() const;

        /// @brief Get the source value as a float
        /// @return float value second operand
        float get_source_float() const;

        /// @brief Get the source operand type of the instruction
        /// @return return LITERAL type
        DexOpcodes::operand_type get_source_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Fill given array with indicated data. Reference
    /// must be an array of primitives. Also used for specifying
    /// switch tables
    /// Example: fill-array-data vAA, +BBBBBBBB
    class Instruction31t : public Instruction {
    private:
        /// @brief array reference (8 bits)
        std::uint8_t vAA;
        /// @brief signed "branch" offset to table data pseudo instruction (32 bits)
        std::int32_t nBBBBBBBB;
        /// @brief type of switch stored by the instruction
        type_of_switch_t type_of_switch;

        /// @brief pointer to one of the types of switch
        switch_type_t switch_instruction;

    public:
        Instruction31t(std::span<uint8_t> bytecode, std::size_t index);

        Instruction31t(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief get the register used as reference for switch/array
        /// @return index of register for reference
        std::uint8_t get_ref_register() const;

        /// @brief Get the type of the reference register
        /// @return return REGISTER type
        DexOpcodes::operand_type get_ref_register_type() const;

        /// @brief Return the offset to the table with packed data
        /// @return offset to packed data
        std::int32_t get_offset() const;

        /// @brief Return the type of the offset
        /// @return return OFFSET type
        DexOpcodes::operand_type get_offset_type() const;

        /// @brief Get the type of switch in case the instruction
        /// is a switch
        /// @return type of switch value
        type_of_switch_t get_type_of_switch() const;

        /// @brief Get the switch instruction pointed by this instruction
        /// @return switch instruction
        switch_type_t get_switch() const;

        /// @brief Set the pointer to the PackedSwitch
        /// @param packed_switch possible instruction pointed
        void set_packed_switch(PackedSwitch *packed_switch);

        /// @brief Set the pointer to the SparseSwitch
        /// @param sparse_switch possible instruction pointed
        void set_sparse_switch(SparseSwitch *sparse_switch);

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move a reference to string specified by given index
    /// into the specified register.
    /// Example: const-string/jumbo vAA, string@BBBBBBBB
    class Instruction31c : public Instruction {
    private:
        /// @brief Destination register (8 bits)
        std::uint8_t vAA;
        /// @brief String index from source (32 bits)
        std::uint32_t iBBBBBBBB;
        /// @brief String value from the instruction
        std::string_view string_value;

    public:
        Instruction31c(std::span<uint8_t> bytecode, std::size_t index);

        Instruction31c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the destination register for the string
        /// @return index of destination register
        std::uint8_t get_destination() const;

        /// @brief Get the destination type of the operand
        /// @return return REGISTER type
        DexOpcodes::operand_type get_destination_type() const;

        /// @brief Get the index of the string operand
        /// @return index of string
        std::uint32_t get_string_idx() const;

        /// @brief Get the type from the string operand
        /// @return return OFFSET type
        DexOpcodes::operand_type get_string_idx_type() const;

        /// @brief Get the value from the string pointed in the instruction
        /// @return constant reference to string value
        std::string_view get_string_value() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Construct array of given type and size, filling it with supplied
    /// contents. Type must be an array type. Array's contents must be
    /// single-word.
    /// Example: filled-new-array {vC, vD, vE, vF, vG}, type@BBBB
    class Instruction35c : public Instruction {
    private:
        /// @brief Size of the array of registers (4 bits)
        std::uint8_t array_size;
        /// @brief Type index (16 bits)
        std::uint16_t type_index;
        /// @brief type value
        kind_type_t type_value;
        /// @brief vector with registers (4 bits each)
        std::vector<std::uint8_t> registers;

    public:
        Instruction35c(std::span<uint8_t> bytecode, std::size_t index);

        Instruction35c(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the number of registers from the instruction
        /// @return array_size value
        std::uint8_t get_number_of_registers() const;

        /// @brief Get a constant reference to the vector with the registers
        /// @return constant reference to registers
        std::span<std::uint8_t> get_registers();

        /// @brief Get the type of the registers operand
        /// @return return REGISTER type
        DexOpcodes::operand_type get_registers_type();

        /// @brief Get the idx of the type
        /// @return value with the type index
        std::uint16_t get_type_idx() const;

        /// @brief Get the type of the value
        /// @return return KIND type
        DexOpcodes::operand_type get_value_type() const;

        /// @brief To get the type of the value
        /// @return type of the array
        shuriken::dex::TYPES::kind get_value_kind() const;

        /// @brief Get the kind value stored
        /// @return kind_type_t of array type
        kind_type_t get_value() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Construct array of given type and size,
    /// filling it with supplied contents.
    /// Example instructions:
    ///     op {vCCCC .. vNNNN}, meth@BBBB
    ///     op {vCCCC .. vNNNN}, site@BBBB
    ///     op {vCCCC .. vNNNN}, type@BBBB
    class Instruction3rc : public Instruction {
    private:
        /// @brief  size of the array
        std::uint8_t array_size;
        /// @brief index of meth, type and call site
        std::uint16_t index;
        /// @brief index value can be a method, type, etc
        kind_type_t index_value;
        /// @brief registers, the registers start by
        /// one first argument register of 16 bits
        std::vector<std::uint16_t> registers;

    public:
        Instruction3rc(std::span<uint8_t> bytecode, std::size_t index);

        Instruction3rc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get number of registers
        /// @return number of registers
        std::uint8_t get_registers_size() const;

        /// @brief Get the numerical value of the index
        /// @return numerical value of the index
        std::uint16_t get_index() const;

        /// @brief Get the value stored of the index
        /// @return type depending on the kind of the instruction
        kind_type_t get_index_value() const;

        /// @brief Get type of the index
        /// @return get KIND type
        DexOpcodes::operand_type get_index_type() const;

        /// @brief To get the type of the array
        /// @return type of the array
        shuriken::dex::TYPES::kind get_value_kind() const;

        /// @brief Get the registers from the instruction
        /// @return constant reference to the registers
        std::span<std::uint16_t> get_registers();

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Invoke indicated signature polymorphic method.
    /// The result (if any) may be stored with an appropriate
    /// move-result* variant as the immediately subsequent
    /// instruction. Example:
    /// invoke-polymorphic {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH
    class Instruction45cc : public Instruction {
    private:
        /// @brief number of registers in the operation
        std::uint8_t reg_count;
        /// @brief registers for the instruction
        std::vector<std::uint8_t> registers;
        /// @brief index to the method called
        std::uint16_t method_reference;
        /// @brief value of the method
        kind_type_t method_value;
        /// @brief index to the prototype
        std::uint16_t prototype_reference;
        /// @brief value of the prototype
        kind_type_t prototype_value;

    public:
        Instruction45cc(std::span<uint8_t> bytecode, std::size_t index);

        Instruction45cc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the number of registers from the instruction
        /// @return number of registers
        std::uint8_t get_number_of_registers() const;

        /// @brief get a constant reference to the registers
        /// @return registers from the instruction
        std::span<std::uint8_t> get_registers();

        /// @brief Get the idx of the method
        /// @return method reference
        std::uint16_t get_method_reference() const;

        /// @brief Get the value from the method
        /// @return method's value
        kind_type_t get_method_value() const;

        /// @brief Get the idx from the prototype
        /// @return prototype reference
        std::uint16_t get_prototype_reference() const;

        /// @brief Get the value from the prototype
        /// @return prototype's value
        kind_type_t get_prototype_value() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Invoke the method handle indicated,
    /// this time it can provide with a range of arguments
    /// given by a size and an initial register.
    /// Example:
    ///     invoke-polymorphic/range {vCCCC .. vNNNN}, meth@BBBB, proto@HHHH
    class Instruction4rcc : public Instruction {
    private:
        /// @brief number of registers in the operation
        std::uint8_t reg_count;
        /// @brief registers for the instruction
        std::vector<std::uint16_t> registers;
        /// @brief index to the method called
        std::uint16_t method_reference;
        /// @brief value of the method
        kind_type_t method_value;
        /// @brief index to the prototype
        std::uint16_t prototype_reference;
        /// @brief value of the prototype
        kind_type_t prototype_value;

    public:
        Instruction4rcc(std::span<uint8_t> bytecode, std::size_t index);

        Instruction4rcc(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        /// @brief Get the number of registers from the instruction
        /// @return number of registers
        std::uint8_t get_number_of_registers() const;

        /// @brief get a constant reference to the registers
        /// @return registers from the instruction
        std::span<std::uint16_t> get_registers();

        /// @brief Get the idx of the method
        /// @return method reference
        std::uint16_t get_method_reference() const;

        /// @brief Get the value from the method
        /// @return method's value
        kind_type_t get_method_value() const;

        /// @brief Get the idx from the prototype
        /// @return prototype reference
        std::uint16_t get_prototype_reference() const;

        /// @brief Get the value from the prototype
        /// @return prototype's value
        kind_type_t get_prototype_value() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Move given literal value into specified register pair
    /// Example: const-wide vAA, #+BBBBBBBBBBBBBBBB
    class Instruction51l : public Instruction {
    private:
        /// @brief destination register (8 bits)
        std::uint8_t vAA;
        /// @brief wide value (64 bits)
        std::int64_t nBBBBBBBBBBBBBBBB;

    public:
        Instruction51l(std::span<uint8_t> bytecode, std::size_t index);

        Instruction51l(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        std::uint8_t get_first_register() const;

        DexOpcodes::operand_type get_first_register_type() const;

        std::int64_t get_wide_value() const;

        double get_wide_value_as_double() const;

        DexOpcodes::operand_type get_wide_value_type() const;

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Packed Switch instruction present in methods
    /// which make use of this kind of data
    class PackedSwitch : public Instruction {
    private:
        /// @brief number of targets
        std::uint16_t size;
        /// @brief first (and lowest) switch case value
        std::int32_t first_key;
        /// @brief targets where the program can jump
        std::vector<std::int32_t> targets;

    public:
        PackedSwitch(std::span<uint8_t> bytecode, std::size_t index);

        PackedSwitch(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        std::uint16_t get_number_of_targets() const;

        std::int32_t get_first_key() const;

        std::span<std::int32_t> get_targets();

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Sparse switch instruction present in methods
    /// which make use of this kind of data, this contain the
    /// keys
    class SparseSwitch : public Instruction {
    private:
        /// @brief Size of keys and targets
        std::uint16_t size;
        /// @brief keys checked and targets
        std::vector<std::pair<std::int32_t, std::int32_t>> keys_targets;

    public:
        SparseSwitch(std::span<uint8_t> bytecode, std::size_t index);

        SparseSwitch(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        std::uint16_t get_size_of_targets() const;

        std::span<std::pair<std::int32_t, std::int32_t>> get_keys_targets();

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief Class present in methods which uses array data
    class FillArrayData : public Instruction {
    private:
        std::uint16_t element_width;
        std::uint32_t size;
        std::vector<std::uint8_t> data;

    public:
        FillArrayData(std::span<uint8_t> bytecode, std::size_t index);

        FillArrayData(std::span<uint8_t> bytecode, std::size_t index, shuriken::parser::dex::Parser *parser);

        std::uint16_t get_element_width() const;

        std::uint32_t get_size_of_data() const;

        std::span<std::uint8_t> get_data();

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };

    /// @brief In case there is an incorrect instruction
    /// this one holds all the opcodes and the length of
    /// previous instruction
    class DalvikIncorrectInstruction : public Instruction {
    public:
        DalvikIncorrectInstruction(std::span<uint8_t> bytecode, std::size_t index, std::uint32_t length);

        /// @brief Return a string with the representation of the instruction
        /// @return string with instruction
        std::string_view print_instruction() override;

        /// @brief Print the instruction on a given stream
        /// @param os stream where to print the instruction
        void print_instruction(std::ostream &os) override;
    };
}// namespace shuriken::disassembler::dex

#endif//SHURIKENLIB_DALVIK_INSTRUCTIONS_H
