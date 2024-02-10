#include "plugin.h"

using namespace BinaryNinja;

static DEXViewType* g_dexViewType = nullptr;

void BinaryNinja::InitDEXViewType() {
    static DEXViewType type;
    BinaryViewType::Register(&type);
    g_dexViewType = &type;
}

extern "C" {
BN_DECLARE_CORE_ABI_VERSION

BINARYNINJAPLUGIN bool CorePluginInit() {
    InitDEXViewType();
    return true;
}
}