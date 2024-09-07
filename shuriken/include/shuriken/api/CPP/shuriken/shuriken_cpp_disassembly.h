

#include "shuriken_enums.h"
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace shurikenapi {

    namespace disassembly {

        class IOperand {
          public:
            virtual ~IOperand() = default;
            IOperand& operator=(IOperand&&) = delete;

            virtual std::int64_t value() const = 0;
            virtual std::string string() const = 0;
        };

        template <typename T> class RegisterOperand : public IOperand {
          public:
            RegisterOperand(T reg) : m_reg(reg){};
            std::int64_t value() const override { return m_reg; }
            std::string string() const override { return "v" + std::to_string(m_reg); }

          private:
            T m_reg = 0;
        };

        template <typename T> class RegisterListOperand : public IOperand {
          public:
            RegisterListOperand(std::span<T> regs) : m_regs(regs.begin(), regs.end()){};
            std::int64_t value() const override { return -1; }
            std::string string() const override {
                std::string str = "{";
                for (size_t i = 0; i < m_regs.size(); ++i) {
                    const auto& reg = m_regs[i];
                    str += "v" + std::to_string(reg);
                    if (i != m_regs.size() - 1)
                        str += ", ";
                }
                str += "}";
                return str;
            }
            const std::vector<T>& getRegs() const { return m_regs; }

          private:
            std::vector<T> m_regs;
        };

        class FieldOperand : public IOperand {
          public:
            FieldOperand(std::uint16_t id, const std::string& name) : m_id(id), m_name(name){};
            std::int64_t value() const override { return m_id; }
            std::string string() const override { return m_name; }

          private:
            std::uint16_t m_id = 0;
            std::string m_name;
        };

        class MethodOperand : public IOperand {
          public:
            MethodOperand(std::uint16_t id, const std::string& name) : m_id(id), m_name(name){};
            std::int64_t value() const override { return m_id; }
            std::string string() const override { return m_name; }

          private:
            std::uint16_t m_id = 0;
            std::string m_name;
        };

        class StringOperand : public IOperand {
          public:
            StringOperand(std::uint16_t id, const std::string& name) : m_id(id), m_name(name){};
            std::int64_t value() const override { return m_id; }
            std::string string() const override { return "\"" + m_name + "\""; }

          private:
            std::uint16_t m_id = 0;
            std::string m_name;
        };

        class Imm8Operand : public IOperand {
          public:
            Imm8Operand(std::int8_t value) : m_value(value){};
            std::int64_t value() const override { return m_value; }
            std::string string() const override {
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << m_value;
                return ss.str();
            }

          private:
            std::uint16_t m_value = 0;
        };

        class Imm16Operand : public IOperand {
          public:
            Imm16Operand(std::uint16_t value) : m_value(value){};
            std::int64_t value() const override { return m_value; }
            std::string string() const override {
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << m_value;
                return ss.str();
            }

          private:
            std::uint16_t m_value = 0;
        };

        class Imm32Operand : public IOperand {
          public:
            Imm32Operand(std::uint32_t value) : m_value(value){};
            std::int64_t value() const override { return m_value; }
            std::string string() const override {
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << m_value;
                return ss.str();
            }

          private:
            std::uint32_t m_value = 0;
        };

        class Imm64Operand : public IOperand {
          public:
            Imm64Operand(std::int64_t value) : m_value(value){};
            std::int64_t value() const override { return m_value; }
            std::string string() const override {
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << m_value;
                return ss.str();
            }

          private:
            std::int64_t m_value = 0;
        };

        class UBranchOperand : public IOperand {
          public:
            UBranchOperand(std::int32_t value, std::int8_t offsetSize) : m_value(value), m_offsetSize(offsetSize){};
            std::int64_t value() const override { return static_cast<uint64_t>(m_value); }
            std::string string() const override {
                std::stringstream ss;
                ss << "+" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << (m_value * m_offsetSize);
                return ss.str();
            }
            std::int8_t getOffsetSize() const { return m_offsetSize; }
            std::uint64_t calculateTarget(std::uint64_t addr) const {
                switch (m_offsetSize) {
                    case 1:
                        return static_cast<std::uint64_t>(static_cast<std::int8_t>(m_value) * 2 + addr);
                    case 2:
                        return static_cast<std::uint64_t>(static_cast<std::int16_t>(m_value) * 2 + addr);
                    case 4:
                        return static_cast<std::uint64_t>(static_cast<std::int32_t>(m_value) * 2 + addr);
                    default:
                        return static_cast<std::uint64_t>(m_value);
                }
            }

          private:
            std::int32_t m_value = 0;
            std::int8_t m_offsetSize = 0;
        };

        class CBranchOperand : public IOperand {
          public:
            CBranchOperand(std::int32_t value, std::int8_t offsetSize) : m_value(value), m_offsetSize(offsetSize){};
            std::int64_t value() const override { return static_cast<uint64_t>(m_value); }
            std::string string() const override {
                std::stringstream ss;
                ss << "+" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << (m_value * m_offsetSize);
                return ss.str();
            }
            std::int8_t getOffsetSize() const { return m_offsetSize; }
            std::uint64_t calculateTrueTarget(std::uint64_t addr) const {
                switch (m_offsetSize) {
                    case 1:
                        return static_cast<std::uint64_t>(static_cast<std::int8_t>(m_value) * 2 + addr);
                    case 2:
                        return static_cast<std::uint64_t>(static_cast<std::int16_t>(m_value) * 2 + addr);
                    case 4:
                        return static_cast<std::uint64_t>(static_cast<std::int32_t>(m_value) * 2 + addr);
                    default:
                        return static_cast<std::uint64_t>(m_value);
                }
            }

          private:
            std::int32_t m_value = 0;
            std::int8_t m_offsetSize = 0;
        };

        class DVMTypeOperand : public IOperand {
          public:
            DVMTypeOperand(std::uint16_t id, const std::string& name) : m_id(id), m_name(name){};
            std::int64_t value() const override { return m_id; }
            std::string string() const override { return m_name; }

          private:
            std::uint16_t m_id = 0;
            std::string m_name;
        };

        class SwitchOperand : public IOperand {
          public:
            SwitchOperand(std::uint32_t tableOffset) : m_tableOffset(tableOffset){};
            std::int64_t value() const override { return m_tableOffset; }
            std::string string() const override {
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << m_tableOffset * 2;
                return ss.str();
            }

          private:
            std::uint32_t m_tableOffset = 0;
        };

        class IMnemonic {
          public:
            virtual ~IMnemonic() = default;
            IMnemonic& operator=(IMnemonic&&) = delete;

            virtual const Mnemonic value() const = 0;
            virtual const std::string& string() const = 0;
        };

        class IInstruction {
          public:
            virtual ~IInstruction() = default;
            IInstruction& operator=(IInstruction&&) = delete;

            virtual const IMnemonic& getMnemonic() const = 0;
            virtual const std::uint32_t getSize() const = 0;
            virtual std::vector<std::reference_wrapper<const IOperand>> getOperands() const = 0;
        };
    } // namespace disassembly

} // namespace shurikenapi