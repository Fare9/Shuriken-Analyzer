#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    namespace details {

        ShurikenClassMethod::ShurikenClassMethod(const std::string& name, const std::string& demangledName,
                                                 std::unique_ptr<IPrototype> prototype, shurikenapi::AccessFlags flags,
                                                 std::span<uint8_t> byteCode)
            : m_name{std::move(name)}, m_demangledName{std::move(demangledName)}, m_prototype{std::move(prototype)}, m_flags{flags},
              m_byteCode{byteCode} {}

        const std::string& ShurikenClassMethod::getName() const {
            return m_name;
        };

        const std::string& ShurikenClassMethod::getDemangledName() const {
            return m_demangledName;
        };

        const IPrototype& ShurikenClassMethod::getPrototype() const {
            return *m_prototype;
        };

        AccessFlags ShurikenClassMethod::getFlags() const {
            return m_flags;
        };

        std::span<uint8_t> ShurikenClassMethod::getByteCode() const {
            return m_byteCode;
        };

    } // namespace details

} // namespace shurikenapi