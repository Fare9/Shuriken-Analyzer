#ifndef SHURIKEN_CPP_CORE_INTERNAL_H
#define SHURIKEN_CPP_CORE_INTERNAL_H

#include "shuriken/shuriken_cpp_core.h"

#include "dex_cpp_core_api_internal.h"
#include "shuriken/parser/shuriken_parsers.h"
#include <memory>
#include <string>

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

        class Prototype : public IPrototype {
          public:
            std::vector<std::reference_wrapper<const IDexTypeInfo>> getParameters() const override {
                std::vector<std::reference_wrapper<const IDexTypeInfo>> parameterRefs;
                for (const auto& entry : m_parameters) {
                    parameterRefs.push_back(std::cref(*entry));
                }
                return parameterRefs;
            }
            const IDexTypeInfo& getReturnType() const override { return *m_returnType; };
            const std::string& getString() const override { return m_string; };

            // --internal
            void setReturnType(std::unique_ptr<IDexTypeInfo> returnType) { m_returnType = std::move(returnType); };
            void addParameter(std::unique_ptr<IDexTypeInfo> returnType) { m_parameters.push_back(std::move(returnType)); };
            void setString(const std::string& name) { m_string = name; };

          private:
            std::unique_ptr<IDexTypeInfo> m_returnType;
            std::vector<std::unique_ptr<IDexTypeInfo>> m_parameters;
            std::string m_string;
        };

        class ClassMethod : public IClassMethod {
          public:
            const std::string& getName() const override { return m_name; };
            const std::string& getDemangledName() const override { return m_demangledName; };
            const IPrototype& getPrototype() const override { return *m_prototype; };
            AccessFlags getFlags() const override { return m_flags; };
            std::span<uint8_t> getByteCode() const override { return m_byteCode; };

            void setName(const std::string& name) { m_name = name; };
            void setFlags(AccessFlags flags) { m_flags = flags; };
            void setPrototype(std::unique_ptr<Prototype> proto) { m_prototype = std::move(proto); };
            void setByteCode(std::span<uint8_t> code) { m_byteCode = code; };
            void setDemangledName(const std::string& name) { m_demangledName = name; };

          private:
            std::string m_name;
            std::string m_demangledName;
            std::unique_ptr<Prototype> m_prototype;
            AccessFlags m_flags;
            std::span<uint8_t> m_byteCode;
        };

        class ClassField : public IClassField {
          public:
            const std::string& getName() const override { return m_name; };
            AccessFlags getAccessFlags() const override { return m_accessFlags; };
            const IDexTypeInfo& getFieldType() const override { return *m_fieldType; };

            void setName(const std::string& name) { m_name = name; };
            void setAccessFlags(AccessFlags flags) { m_accessFlags = flags; };
            void setFieldType(std::unique_ptr<IDexTypeInfo> fieldType) { m_fieldType = std::move(fieldType); };

          private:
            std::string m_name;
            AccessFlags m_accessFlags;
            std::unique_ptr<IDexTypeInfo> m_fieldType;
        };
        class DexClass : public IDexClass {
          public:
            const std::string& getName() const override { return m_name; };
            const std::string& getSuperClassName() const override { return m_superClassName; }
            const std::string& getSourceFileName() const override { return m_sourceFileName; }
            AccessFlags getAccessFlags() const override { return m_accessFlags; };
            std::vector<std::reference_wrapper<const IClassField>> getStaticFields() const override {
                std::vector<std::reference_wrapper<const IClassField>> fieldRefs;
                for (const auto& entry : m_staticFields) {
                    fieldRefs.push_back(std::cref(*entry));
                }
                return fieldRefs;
            }
            std::vector<std::reference_wrapper<const IClassField>> getInstanceFields() const override {
                std::vector<std::reference_wrapper<const IClassField>> fieldRefs;
                for (const auto& entry : m_instanceFields) {
                    fieldRefs.push_back(std::cref(*entry));
                }
                return fieldRefs;
            }
            std::vector<std::reference_wrapper<const IClassMethod>> getDirectMethods() const override {
                std::vector<std::reference_wrapper<const IClassMethod>> methodRefs;
                for (const auto& entry : m_directMethods) {
                    methodRefs.push_back(std::cref(*entry));
                }
                return methodRefs;
            }
            std::vector<std::reference_wrapper<const IClassMethod>> getVirtualMethods() const override {
                std::vector<std::reference_wrapper<const IClassMethod>> methodRefs;
                for (const auto& entry : m_virtualMethods) {
                    methodRefs.push_back(std::cref(*entry));
                }
                return methodRefs;
            }

            // --Internal
            void setName(const std::string& name) { m_name = name; };
            void setSuperClassName(const std::string& name) { m_superClassName = name; };
            void setSourceFileName(const std::string& name) { m_sourceFileName = name; };
            void setAccessFlags(AccessFlags flags) { m_accessFlags = flags; };
            void addStaticField(std::unique_ptr<IClassField> entry) { m_staticFields.push_back(std::move(entry)); };
            void addInstanceField(std::unique_ptr<IClassField> entry) { m_instanceFields.push_back(std::move(entry)); };
            void addDirectMethod(std::unique_ptr<IClassMethod> entry) { m_directMethods.push_back(std::move(entry)); };
            void addVirtualMethod(std::unique_ptr<IClassMethod> entry) { m_virtualMethods.push_back(std::move(entry)); };

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
            void addClass(std::unique_ptr<IDexClass> entry);

          private:
            std::vector<std::unique_ptr<IDexClass>> m_classes;
        };

        class ShurikenDex : public IDex {
          public:
            ShurikenDex(const std::string& filePath);
            const DexHeader& getHeader() const override;
            const IClassManager& getClassManager() const override;

          private:
            void createFieldEntry(shuriken::parser::dex::EncodedField* data, details::ClassField* fieldEntry);
            std::unique_ptr<IDexTypeInfo> createTypeInfo(shuriken::parser::dex::DVMType* rawType);

            std::unique_ptr<shuriken::parser::dex::Parser> m_parser;
            ShurikenClassManager m_classManager;
            DexHeader m_header;
        };

    } // namespace details
} // namespace shurikenapi

#endif // SHURIKEN_CPP_CORE_INTERNAL_H