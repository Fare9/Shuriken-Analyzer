#pragma once

#include "binaryninjaapi.h"
#include <cstdint>

namespace BinaryNinja {

class DEXViewType : public BinaryViewType {
    Ref<Logger> m_logger;

  public:
    DEXViewType();
    virtual Ref<BinaryView> Create(BinaryView* data) override;
    virtual Ref<BinaryView> Parse(BinaryView* data) override;
    virtual bool IsTypeValidForData(BinaryView* data) override;
    virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
};
void InitDEXViewType();

class DEXView : public BinaryView {
  public:
    DEXView(BinaryView* data, bool parseOnly = false);

    virtual bool Init() override;

  protected:
    virtual uint64_t PerformGetEntryPoint() const override;

    virtual bool PerformIsExecutable() const override { return true; }
    virtual BNEndianness PerformGetDefaultEndianness() const override { return LittleEndian; }
    virtual bool PerformIsRelocatable() const override { return m_relocatable; }
    virtual size_t PerformGetAddressSize() const override;

  private:
    bool m_relocatable = false;
    bool m_parseOnly;
    bool m_backedByDatabase;
    Ref<Logger> m_logger;
    Ref<Architecture> m_arch;
};

} // namespace BinaryNinja