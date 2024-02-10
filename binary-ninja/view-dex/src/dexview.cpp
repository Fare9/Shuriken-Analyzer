#include "plugin.h"

namespace BinaryNinja {

DEXView::DEXView(BinaryView* data, bool parseOnly) : BinaryView("DEX", data->GetFile(), data), m_parseOnly(parseOnly) {
    CreateLogger("BinaryView");
    m_logger = CreateLogger("BinaryView.DEXView");
    m_backedByDatabase = data->GetFile()->IsBackedByDatabase("DEX");
}

bool DEXView::Init() {
    Ref<Settings> settings = GetLoadSettings(GetTypeName());
    Ref<Settings> viewSettings = Settings::Instance();

    const uint64_t alignment = 0x1000;
    uint64_t baseAddress = 0;
    const uint64_t rawFileOffset = 0;
    const uint64_t dexCodeSegmentSize = (GetParentView()->GetLength() + alignment - 1) & ~(alignment - 1);
    const uint64_t fieldDataSegmentAddress = baseAddress + dexCodeSegmentSize;
    const uint64_t fieldDataSegmentSize = 0x1000;

    // TODO: create/use arch-dex
    Ref<Architecture> arch = Architecture::GetByName("x86");
    SetDefaultArchitecture(arch);
    Ref<Platform> platform = arch->GetStandalonePlatform();
    SetDefaultPlatform(platform);

    AddAutoSegment(baseAddress, GetParentView()->GetLength(), rawFileOffset, GetParentView()->GetLength(), SegmentReadable);
    AddAutoSegment(fieldDataSegmentAddress, fieldDataSegmentSize, 0, 0x100, SegmentWritable);

    AddAutoSection("code", 0, dexCodeSegmentSize, ReadOnlyDataSectionSemantics);
    AddAutoSection("fields", fieldDataSegmentAddress, fieldDataSegmentSize, ReadWriteDataSectionSemantics);

    return true;
}

uint64_t DEXView::PerformGetEntryPoint() const { return 0; }

size_t DEXView::PerformGetAddressSize() const { return 8; }

} // namespace BinaryNinja