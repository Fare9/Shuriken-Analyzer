#include "dex_cpp_core_api_internal.h"
#include "shuriken/exceptions/invalidinstruction_exception.h"

using shuriken::disassembler::dex::DexOpcodes;
using shurikenapi::disassembly::IOperand;

namespace shurikenapi {
    namespace details {

        class ShurikenMnemonic : public shurikenapi::disassembly::IMnemonic {
          public:
            void set(shurikenapi::disassembly::Mnemonic mnemonic) { m_mnemonic = mnemonic; }

            const shurikenapi::disassembly::Mnemonic value() const { return m_mnemonic; }
            const std::string& string() const { return shurikenapi::disassembly::opcodeNames.at(m_mnemonic); }

          private:
            shurikenapi::disassembly::Mnemonic m_mnemonic;
        };

        class ShurikenInstruction : public shurikenapi::disassembly::IInstruction {
          public:
            // IInstruction overrides - Public facing APIs
            const shurikenapi::disassembly::IMnemonic& getMnemonic() const override { return std::cref(*m_mnemonic); }
            const std::uint32_t getSize() const override { return m_size; }

            std::vector<std::reference_wrapper<const IOperand>> getOperands() const override {
                std::vector<std::reference_wrapper<const IOperand>> operandRefs;
                for (const auto& entry : m_operands) {
                    operandRefs.push_back(std::cref(*entry));
                }
                return operandRefs;
            };

            // Internal routines for generation
            void addOperand(std::unique_ptr<IOperand> op) { m_operands.push_back(std::move(op)); }

            void setMnemonic(shurikenapi::disassembly::Mnemonic mnemonic) {
                m_mnemonic = std::make_unique<ShurikenMnemonic>();
                m_mnemonic->set(mnemonic);
            }

            void setSize(std::uint32_t size) { m_size = size; }

          private:
            std::uint32_t m_size;
            std::unique_ptr<ShurikenMnemonic> m_mnemonic;
            std::vector<std::unique_ptr<IOperand>> m_operands;
        };

        std::unique_ptr<shurikenapi::disassembly::IInstruction> ShurikenDex::decodeInstruction(std::span<std::uint8_t> byteCode) const {
            // std::cout << "Disassembler: decodeInstruction" << std::endl;

            // Disassemble the bytecode
            printf("Processing: %02X", byteCode[0]);
            DexOpcodes::opcodes opcode = static_cast<DexOpcodes::opcodes>(byteCode[0]);
            std::unique_ptr<shuriken::disassembler::dex::Instruction> instr =
                m_disassembler->disassemble_instruction(static_cast<std::uint32_t>(opcode), byteCode, 0);

            if (!instr) {
                printf("\nFailed to disassemble instruction: %02X\n", byteCode[0]);
                return nullptr;
            }

            printf(" - Type: %d\n", instr->get_instruction_type());

            auto newInstruction = std::make_unique<ShurikenInstruction>();
            newInstruction->setMnemonic(static_cast<shurikenapi::disassembly::Mnemonic>(opcode));

            switch (instr->get_instruction_type()) {
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION10X: {
                    newInstruction->setSize(instr->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION12X: {
                    shuriken::disassembler::dex::Instruction12x* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction12x*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION11N: {
                    shuriken::disassembler::dex::Instruction11n* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction11n*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createImm8(insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION11X: {
                    shuriken::disassembler::dex::Instruction11x* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction11x*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->setSize(insn->get_instruction_length());

                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION10T: {
                    shuriken::disassembler::dex::Instruction10t* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction10t*>(instr.get());
                    newInstruction->addOperand(creatUnconditionalBranch(static_cast<std::int32_t>(insn->get_offset()), 1));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION20T: {
                    shuriken::disassembler::dex::Instruction20t* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction20t*>(instr.get());
                    newInstruction->addOperand(creatUnconditionalBranch(static_cast<std::int32_t>(insn->get_offset()), 2));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION22X: {
                    shuriken::disassembler::dex::Instruction22x* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction22x*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION21T: {
                    shuriken::disassembler::dex::Instruction21t* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction21t*>(instr.get());
                    newInstruction->addOperand(createConditionalBranch(static_cast<std::int32_t>(insn->get_jump_offset()), 2));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION21H: {
                    shuriken::disassembler::dex::Instruction21h* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction21h*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createImm64(insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION21C: {
                    shuriken::disassembler::dex::Instruction21c* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction21c*>(instr.get());

                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createOperandFromSourceId(insn->get_source_as_kind(), insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION21S: {
                    shuriken::disassembler::dex::Instruction21s* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction21s*>(instr.get());

                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createImm16(insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION22B: {
                    shuriken::disassembler::dex::Instruction22b* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction22b*>(instr.get());

                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_first_operand()));
                    newInstruction->addOperand(createImm8(insn->get_second_operand()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION22C: {
                    shuriken::disassembler::dex::Instruction22c* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction22c*>(instr.get());

                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_operand()));
                    newInstruction->addOperand(createOperandFromSourceId(insn->get_checked_id_as_kind(), insn->get_checked_id()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION23X: {
                    shuriken::disassembler::dex::Instruction23x* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction23x*>(instr.get());

                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_first_source()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_second_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION22T: {
                    shuriken::disassembler::dex::Instruction22t* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction22t*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_first_operand()));
                    newInstruction->addOperand(createRegisterOperand(insn->get_second_operand()));
                    newInstruction->addOperand(createConditionalBranch(static_cast<std::int32_t>(insn->get_offset()), 2));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION31I: {
                    shuriken::disassembler::dex::Instruction31i* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction31i*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_destination()));
                    newInstruction->addOperand(createImm32(insn->get_source()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION31T: {
                    shuriken::disassembler::dex::Instruction31t* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction31t*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_ref_register()));
                    newInstruction->addOperand(createSwitch(insn->get_offset()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION35C: {
                    shuriken::disassembler::dex::Instruction35c* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction35c*>(instr.get());
                    newInstruction->addOperand(createRegisterList(insn->get_registers()));
                    newInstruction->addOperand(createOperandFromSourceId(insn->get_array_value(), insn->get_type_idx()));

                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION3RC: {
                    shuriken::disassembler::dex::Instruction3rc* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction3rc*>(instr.get());
                    newInstruction->addOperand(createRegisterList(insn->get_registers()));
                    newInstruction->addOperand(createOperandFromSourceId(insn->get_index_value(), insn->get_index()));

                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                case DexOpcodes::dexinsttype::DEX_INSTRUCTION51L: {
                    shuriken::disassembler::dex::Instruction51l* insn =
                        dynamic_cast<shuriken::disassembler::dex::Instruction51l*>(instr.get());
                    newInstruction->addOperand(createRegisterOperand(insn->get_first_register()));
                    newInstruction->addOperand(createImm64(insn->get_wide_value()));
                    newInstruction->setSize(insn->get_instruction_length());
                    break;
                }
                default: {
                    char errMsg[1024];
                    sprintf(errMsg, "Unhandled Instruction Type: %d\n", instr->get_instruction_type());
                    printf("Unhandled Instruction Type: %d\n", instr->get_instruction_type());
                    throw exceptions::InvalidInstructionException(errMsg, 0);

                    return nullptr;
                }
            }

            return newInstruction;
        }

    } // namespace details
} // namespace shurikenapi