#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    // --Main API Function----
    SHURIKENLIB_API std::unique_ptr<IDex> parse_dex(const std::string& filePath) {
        std::unique_ptr<IDex> output = std::make_unique<details::ShurikenDex>(filePath);
        return output;
    }

} // namespace shurikenapi