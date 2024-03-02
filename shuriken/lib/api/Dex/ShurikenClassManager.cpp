#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    namespace details {

        void ShurikenClassManager::addClass(std::unique_ptr<IDexClass> entry) {
            m_classes.push_back(std::move(entry));
        }

        std::vector<std::reference_wrapper<const IDexClass>> ShurikenClassManager::getAllClasses() const {
            std::vector<std::reference_wrapper<const IDexClass>> classRefs;
            for (const auto& entry : m_classes) {
                classRefs.push_back(std::cref(*entry));
            }
            return classRefs;
        };

    } // namespace details

} // namespace shurikenapi