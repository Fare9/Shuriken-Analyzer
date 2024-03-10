#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    namespace details {

        ShurikenClassField::ShurikenClassField(const std::string& name, shurikenapi::AccessFlags flags,
                                               std::unique_ptr<IDexTypeInfo> fieldType)
            : m_name{std::move(name)}, m_accessFlags{std::move(flags)}, m_fieldType{std::move(fieldType)} {}

        const std::string& ShurikenClassField::getName() const {
            return m_name;
        };

        AccessFlags ShurikenClassField::getAccessFlags() const {
            return m_accessFlags;
        };

        const IDexTypeInfo& ShurikenClassField::getFieldType() const {
            return *m_fieldType;
        };

    } // namespace details

} // namespace shurikenapi