#include "plugin.h"

SmaliArchitecture::SmaliArchitecture(const char* name, BNEndianness endian) : BinaryNinja::Architecture(name) {
    m_endian = endian;
}

BNEndianness SmaliArchitecture::GetEndianness() const { return m_endian; }

size_t SmaliArchitecture::GetAddressSize() const { return 4; }

bool SmaliArchitecture::GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen,
                                           BinaryNinja::InstructionInfo& result) {
    return false;
}

bool SmaliArchitecture::GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len,
                                           std::vector<BinaryNinja::InstructionTextToken>& result) {
    return false;
}
