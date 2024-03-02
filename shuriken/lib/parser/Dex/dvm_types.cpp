//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dvm_types.cpp

#include "shuriken/shuriken_cpp_core.h"
#include "shuriken/common/Dex/dvm_types.h"
#include <unordered_map>

using namespace shuriken::dex;
using namespace shuriken::dex::TYPES;

static const std::unordered_map<access_flags, std::string> flagStrings = {
        {ACC_PUBLIC, "PUBLIC"},
        {ACC_PRIVATE, "PRIVATE"},
        {ACC_PROTECTED, "PROTECTED"},
        {ACC_STATIC, "STATIC"},
        {ACC_FINAL, "FINAL"},
        {ACC_SYNCHRONIZED, "SYNCHRONIZED"},
        {ACC_VOLATILE, "VOLATILE"},
        {ACC_BRIDGE, "BRIDGE"},
        {ACC_TRANSIENT, "TRANSIENT"},
        {ACC_VARARGS, "VARARGS"},
        {ACC_NATIVE, "NATIVE"},
        {ACC_INTERFACE, "INTERFACE"},
        {ACC_ABSTRACT, "ABSTRACT"},
        {ACC_STRICT, "STRICT"},
        {ACC_SYNTHETIC, "SYNTHETIC"},
        {ACC_ANNOTATION, "ANNOTATION"},
        {ACC_ENUM, "ENUM"},
        {UNUSED, "UNUSED"},
        {ACC_CONSTRUCTOR, "CONSTRUCTOR"},
        {ACC_DECLARED_SYNCHRONIZED, "DECLARED_SYNCHRONIZED"}};

namespace shurikenapi::utils {

SHURIKENLIB_API std::string DexFlags2String(shurikenapi::AccessFlags ac) {
    return Utils::get_types_as_string(static_cast<TYPES::access_flags>(ac));
}

}

std::string Utils::get_types_as_string(TYPES::access_flags ac) {
    std::string ac_str = "";
    for (auto &[key, value]: flagStrings) {
        if ((key & ac) == key) {
            ac_str += value + "|";
        }
    }

    if (ac_str.ends_with("|"))
        ac_str.erase(ac_str.size() - 1);

    return ac_str;
}