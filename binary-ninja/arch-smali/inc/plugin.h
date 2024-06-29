#pragma once

#include "binaryninjaapi.h"
#include <string>
#include <vector>

class SmaliArchitecture : public BinaryNinja::Architecture {
  public:
    SmaliArchitecture(const char* name, BNEndianness endian);

    BNEndianness GetEndianness() const override;
    size_t GetAddressSize() const override;
    bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen,
                            BinaryNinja::InstructionInfo& result) override;
    bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
                            std::vector<BinaryNinja::InstructionTextToken>& result) override;

  private:
    BNEndianness m_endian;
};