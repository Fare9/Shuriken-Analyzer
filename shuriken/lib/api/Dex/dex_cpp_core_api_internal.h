#ifndef SHURIKEN_CPP_CORE_INTERNAL_H
#define SHURIKEN_CPP_CORE_INTERNAL_H

#include "shuriken/shuriken_cpp_core.h"

#include "dex_cpp_core_api_internal.h"
#include "shuriken/disassembler/Dex/dex_disassembler.h"
#include "shuriken/parser/shuriken_parsers.h"
#include <memory>
#include <string>

/*
Implementation classes of the C++ public API.
*/
namespace shurikenapi {
    namespace details {

        class DexTypeInfo : public IDexTypeInfo {
          public:
            DexType getType() const override { return m_dexType; };
            std::optional<FundamentalValue> getFundamentalValue() const override {
                if (m_dexType == DexType::kFundamental && m_value.has_value()) {
                    return std::get<FundamentalValue>(m_value.value());
                }
                return std::nullopt;
            };
            void setFundamentalValue(FundamentalValue value) { m_value = value; };
            void setType(DexType type) {
                m_dexType = type;
                if (type != DexType::kFundamental) {
                    m_value = std::nullopt;
                }
            }

          private:
            DexType m_dexType;
            std::optional<std::variant<FundamentalValue>> m_value = std::nullopt;
        };

        class ShurikenPrototype : public IPrototype {
          public:
            explicit ShurikenPrototype(const std::string& string, std::unique_ptr<IDexTypeInfo> returnType,
                                       std::vector<std::unique_ptr<IDexTypeInfo>> parameters);

            std::vector<std::reference_wrapper<const IDexTypeInfo>> getParameters() const override;
            const IDexTypeInfo& getReturnType() const override;
            const std::string& getString() const override;

          private:
            std::unique_ptr<IDexTypeInfo> m_returnType;
            std::vector<std::unique_ptr<IDexTypeInfo>> m_parameters;
            std::string m_string;
        };

        class ShurikenClassMethod : public IClassMethod {
          public:
            explicit ShurikenClassMethod(const std::string& name, const std::string& dalvikName, const std::string& demangledName,
                                         std::unique_ptr<IPrototype> prototype, shurikenapi::AccessFlags flags,
                                         std::span<uint8_t> byteCode, std::uint64_t codeLocation);
            const std::string& getName() const override;
            const std::string& getDalvikName() const override;
            const std::string& getDemangledName() const override;
            const IPrototype& getPrototype() const override;
            AccessFlags getFlags() const override;
            std::span<uint8_t> getByteCode() const override;
            std::uint64_t getCodeLocation() const override;

          private:
            std::string m_name;
            std::string m_dalvikName;
            std::string m_demangledName;
            std::unique_ptr<IPrototype> m_prototype;
            AccessFlags m_flags;
            std::span<uint8_t> m_byteCode;
            std::uint64_t m_codeLocation;
        };

        class ShurikenClassField : public IClassField {
          public:
            explicit ShurikenClassField(const std::string& name, shurikenapi::AccessFlags flags,
                                        std::unique_ptr<IDexTypeInfo> fieldType);
            const std::string& getName() const override;
            AccessFlags getAccessFlags() const override;
            const IDexTypeInfo& getFieldType() const override;

          private:
            std::string m_name;
            AccessFlags m_accessFlags;
            std::unique_ptr<IDexTypeInfo> m_fieldType;
        };
        class ShurikenDexClass : public IDexClass {
          public:
            explicit ShurikenDexClass(const std::string& className, const std::string& superName, const std::string& sourceName,
                                      shurikenapi::AccessFlags accessFlags);
            const std::string& getName() const override;
            const std::string& getSuperClassName() const override;
            const std::string& getSourceFileName() const override;
            AccessFlags getAccessFlags() const override;
            std::vector<std::reference_wrapper<const IClassField>> getStaticFields() const override;
            std::vector<std::reference_wrapper<const IClassField>> getInstanceFields() const override;
            std::vector<std::reference_wrapper<const IClassMethod>> getDirectMethods() const override;
            std::vector<std::reference_wrapper<const IClassMethod>> getVirtualMethods() const override;

            // --Internal
            void addStaticField(std::unique_ptr<IClassField> entry);
            void addInstanceField(std::unique_ptr<IClassField> entry);
            void addDirectMethod(std::unique_ptr<IClassMethod> entry);
            void addVirtualMethod(std::unique_ptr<IClassMethod> entry);

          private:
            std::string m_name;
            std::string m_superClassName;
            std::string m_sourceFileName;
            AccessFlags m_accessFlags;
            std::vector<std::unique_ptr<IClassField>> m_staticFields;
            std::vector<std::unique_ptr<IClassField>> m_instanceFields;
            std::vector<std::unique_ptr<IClassMethod>> m_directMethods;
            std::vector<std::unique_ptr<IClassMethod>> m_virtualMethods;
        };

        class ShurikenClassManager : public IClassManager {
          public:
            std::vector<std::reference_wrapper<const IDexClass>> getAllClasses() const override;

            // --Internal
            void addClass(std::unique_ptr<IDexClass> entry);

          private:
            std::vector<std::unique_ptr<IDexClass>> m_classes;
        };

        class ShurikenDex : public IDex, public IDisassembler{
          public:
            ShurikenDex(const std::string& filePath);
            const DexHeader& getHeader() const override;
            const IClassManager& getClassManager() const override;

            void processFields(shuriken::parser::dex::ClassDataItem& classDataItem, details::ShurikenDexClass& classEntry);
            std::unique_ptr<IClassMethod> processMethods(shuriken::parser::dex::EncodedMethod* data);
            const IDisassembler& getDisassembler() const override {
              return static_cast<const IDisassembler&>(*this);
            }

            void sayHello() const override {
              std::cout << "Hello from Disassembler" << std::endl;
            }

          private:
            std::unique_ptr<details::ShurikenClassField> createFieldEntry(shuriken::parser::dex::EncodedField* data);
            std::unique_ptr<IDexTypeInfo> createTypeInfo(shuriken::parser::dex::DVMType* rawType);

            // The order of these 2 is important.
            std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> m_disassembler;
            std::unique_ptr<shuriken::parser::dex::Parser> m_parser;

            ShurikenClassManager m_classManager;
            DexHeader m_header;
        };

    } // namespace details
} // namespace shurikenapi

#endif // SHURIKEN_CPP_CORE_INTERNAL_H