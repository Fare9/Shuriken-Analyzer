#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    namespace details {

        ShurikenDexClass::ShurikenDexClass(uint32_t id, const std::string& className, const std::string& superName, const std::string& sourceName,
                                           shurikenapi::AccessFlags accessFlags)
            : m_name{className}, m_superClassName{superName}, m_sourceFileName{sourceName}, m_accessFlags{accessFlags}, m_classId{id} {}

        const std::string& ShurikenDexClass::getName() const {
            return m_name;
        };

        const std::string& ShurikenDexClass::getSuperClassName() const {
            return m_superClassName;
        }

        const std::string& ShurikenDexClass::getSourceFileName() const {
            return m_sourceFileName;
        }

        AccessFlags ShurikenDexClass::getAccessFlags() const {
            return m_accessFlags;
        };

        std::vector<std::reference_wrapper<const IClassField>> ShurikenDexClass::getStaticFields() const {
            std::vector<std::reference_wrapper<const IClassField>> fieldRefs;
            for (const auto& entry : m_staticFields) {
                fieldRefs.push_back(std::cref(*entry));
            }
            return fieldRefs;
        }

        std::vector<std::reference_wrapper<const IClassField>> ShurikenDexClass::getInstanceFields() const {
            std::vector<std::reference_wrapper<const IClassField>> fieldRefs;
            for (const auto& entry : m_instanceFields) {
                fieldRefs.push_back(std::cref(*entry));
            }
            return fieldRefs;
        }

        std::vector<std::reference_wrapper<const IClassMethod>> ShurikenDexClass::getDirectMethods() const {
            std::vector<std::reference_wrapper<const IClassMethod>> methodRefs;
            for (const auto& entry : m_directMethods) {
                methodRefs.push_back(std::cref(*entry));
            }
            return methodRefs;
        }

        std::vector<std::reference_wrapper<const IClassMethod>> ShurikenDexClass::getVirtualMethods() const {
            std::vector<std::reference_wrapper<const IClassMethod>> methodRefs;
            for (const auto& entry : m_virtualMethods) {
                methodRefs.push_back(std::cref(*entry));
            }
            return methodRefs;
        }

        std::vector<std::reference_wrapper<const IClassMethod>> ShurikenDexClass::getExternalMethods() const {
            std::vector<std::reference_wrapper<const IClassMethod>> methodRefs;
            for (const auto& entry : m_externalMethods) {
                methodRefs.push_back(std::cref(*entry));
            }
            return methodRefs;
        }

        void ShurikenDexClass::addStaticField(std::unique_ptr<IClassField> entry) {
            m_staticFields.push_back(std::move(entry));
        };

        void ShurikenDexClass::addInstanceField(std::unique_ptr<IClassField> entry) {
            m_instanceFields.push_back(std::move(entry));
        };

        void ShurikenDexClass::addDirectMethod(std::unique_ptr<IClassMethod> entry) {
            m_directMethods.push_back(std::move(entry));
        };

        void ShurikenDexClass::addVirtualMethod(std::unique_ptr<IClassMethod> entry) {
            m_virtualMethods.push_back(std::move(entry));
        };

        void ShurikenDexClass::addExternalMethod(std::unique_ptr<IClassMethod> entry) {
            m_externalMethods.push_back(std::move(entry));
        };

    } // namespace details

} // namespace shurikenapi