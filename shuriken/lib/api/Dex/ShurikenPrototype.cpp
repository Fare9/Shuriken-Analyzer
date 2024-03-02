#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    namespace details {

        ShurikenPrototype::ShurikenPrototype(const std::string& string, std::unique_ptr<IDexTypeInfo> returnType,
                                             std::vector<std::unique_ptr<IDexTypeInfo>> parameters)
            : m_string{std::move(string)}, m_returnType{std::move(returnType)}, m_parameters{std::move(parameters)} {}

        std::vector<std::reference_wrapper<const IDexTypeInfo>> ShurikenPrototype::getParameters() const {
            std::vector<std::reference_wrapper<const IDexTypeInfo>> parameterRefs;
            for (const auto& entry : m_parameters) {
                parameterRefs.push_back(std::cref(*entry));
            }
            return parameterRefs;
        }

        const IDexTypeInfo& ShurikenPrototype::getReturnType() const {
            return *m_returnType;
        };
        const std::string& ShurikenPrototype::getString() const {
            return m_string;
        };

    } // namespace details

} // namespace shurikenapi