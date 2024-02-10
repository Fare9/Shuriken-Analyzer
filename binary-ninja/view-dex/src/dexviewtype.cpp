#include "plugin.h"
#include <string>
#include <vector>

namespace BinaryNinja {

DEXViewType::DEXViewType() : BinaryViewType("DEX", "Dalvik Executable Format") { m_logger = LogRegistry::CreateLogger("BinaryView"); }

Ref<BinaryView> DEXViewType::Create(BinaryView* data) {

    try {
        return new DEXView(data);
    } catch (std::exception& e) {
        m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
        return nullptr;
    }
}

Ref<BinaryView> DEXViewType::Parse(BinaryView* data) {

    try {
        return new DEXView(data, true);
    } catch (std::exception& e) {
        m_logger->LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
        return nullptr;
    }
}

bool DEXViewType::IsTypeValidForData(BinaryView* data) {

    const uint8_t dex_magic[] = {'d', 'e', 'x', '\n'};

    DataBuffer sig = data->ReadBuffer(0, 4);
    if (sig.GetLength() != 4)
        return false;
    if (memcmp(sig.GetData(), dex_magic, 4) != 0)
        return false;

    return true;
}

Ref<Settings> DEXViewType::GetLoadSettingsForData(BinaryView* data) {

    Ref<BinaryView> viewRef = Parse(data);
    if (!viewRef || !viewRef->Init()) {
        m_logger->LogError("View type '%s' could not be created", GetName().c_str());
        return nullptr;
    }

    Ref<Settings> settings = GetDefaultLoadSettingsForData(viewRef);

    // specify default load settings that can be overridden
    std::vector<std::string> overrides = {"loader.architecture", "loader.imageBase", "loader.platform"};
    if (!viewRef->IsRelocatable())
        settings->UpdateProperty("loader.imageBase", "message", "Note: File indicates image is not relocatable.");

    for (const auto& override : overrides) {
        if (settings->Contains(override))
            settings->UpdateProperty(override, "readOnly", false);
    }

    return settings;
}

} // namespace BinaryNinja