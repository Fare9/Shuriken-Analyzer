#include "dex_cpp_core_api_internal.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>

using shurikenapi::disassembly::IOperand;
using shurikenapi::disassembly::UBranchOperand;
using shurikenapi::disassembly::CBranchOperand;
using shurikenapi::disassembly::RegisterOperand;
using shurikenapi::disassembly::RegisterListOperand;
using shurikenapi::disassembly::Imm8Operand;
using shurikenapi::disassembly::Imm16Operand;
using shurikenapi::disassembly::Imm32Operand;
using shurikenapi::disassembly::Imm64Operand;
using shurikenapi::disassembly::DVMTypeOperand;
using shurikenapi::disassembly::FieldOperand;
using shurikenapi::disassembly::MethodOperand;
using shurikenapi::disassembly::StringOperand;
using shurikenapi::disassembly::SwitchOperand;


namespace shurikenapi {
    namespace details {

        std::unique_ptr<IOperand> ShurikenDex::createRegisterOperand(std::uint8_t reg) const {
            return std::make_unique<RegisterOperand<std::uint8_t>>(reg);
        }

        std::unique_ptr<IOperand> ShurikenDex::createRegisterOperand(std::uint16_t reg) const {
            return std::make_unique<RegisterOperand<std::uint16_t>>(reg);
        }

        std::unique_ptr<IOperand> ShurikenDex::createRegisterList(std::span<std::uint8_t> regs) const {
            return std::make_unique<RegisterListOperand<std::uint8_t>>(regs);
        }

        std::unique_ptr<IOperand> ShurikenDex::createRegisterList(std::span<std::uint16_t> regs) const {
            return std::make_unique<RegisterListOperand<std::uint16_t>>(regs);
        }

        std::unique_ptr<IOperand> ShurikenDex::creatUnconditionalBranch(std::int32_t value, std::int8_t offsetSize) const {
            return std::make_unique<UBranchOperand>(value, offsetSize);
        }

        std::unique_ptr<IOperand> ShurikenDex::createConditionalBranch(std::int32_t value, std::int8_t offsetSize) const {
            return std::make_unique<CBranchOperand>(value, offsetSize);
        }

        std::unique_ptr<IOperand> ShurikenDex::createImm8(std::int8_t value) const {
            return std::make_unique<Imm8Operand>(value);
        }

        std::unique_ptr<IOperand> ShurikenDex::createImm16(std::int16_t value) const {
            return std::make_unique<Imm16Operand>(value);
        }

        std::unique_ptr<IOperand> ShurikenDex::createImm32(std::int32_t value) const {
            return std::make_unique<Imm32Operand>(value);
        }

        std::unique_ptr<IOperand> ShurikenDex::createImm64(std::int64_t value) const {
            return std::make_unique<Imm64Operand>(value);
        }

        std::unique_ptr<IOperand> ShurikenDex::createSwitch(std::uint32_t tableOffset) const {
            return std::make_unique<SwitchOperand>(tableOffset);
        }

        std::unique_ptr<IOperand> ShurikenDex::createOperandFromSourceId(shuriken::disassembler::dex::kind_type_t source_id,
                                                                         std::uint16_t iBBBB) const {
            if (std::holds_alternative<std::monostate>(source_id)) {
                printf("Monostate\n");
                exit(-1);
            } else if (std::holds_alternative<shuriken::parser::dex::DVMType*>(source_id)) {
                auto type = std::get<shuriken::parser::dex::DVMType*>(source_id);
                return std::make_unique<DVMTypeOperand>(iBBBB, std::string(type->get_raw_type()));
            } else if (std::holds_alternative<shuriken::parser::dex::FieldID*>(source_id)) {
                auto field = std::get<shuriken::parser::dex::FieldID*>(source_id);
                return std::make_unique<FieldOperand>(iBBBB, field->pretty_field());
            } else if (std::holds_alternative<shuriken::parser::dex::MethodID*>(source_id)) {
                auto method = std::get<shuriken::parser::dex::MethodID*>(source_id);
                return std::make_unique<MethodOperand>(iBBBB, std::string(method->dalvik_name_format()));
            } else if (std::holds_alternative<shuriken::parser::dex::ProtoID*>(source_id)) {
                printf("ProtoID");
                exit(-1);
            } else if (std::holds_alternative<std::string_view>(source_id)) {
                auto str = std::get<std::string_view>(source_id);
                return std::make_unique<StringOperand>(iBBBB, std::string(str));
            } else {
                printf("Unknown\n");
                exit(-1);
            }

            return nullptr;
        }

    } // namespace details
} // namespace shurikenapi