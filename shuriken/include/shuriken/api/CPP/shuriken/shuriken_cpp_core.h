#ifndef SHURIKEN_CPP_CORE_H
#define SHURIKEN_CPP_CORE_H

#include "shuriken_structs.h"

#if defined(_WIN32) || defined(__WIN32__)
    #ifdef SHURIKENLIB_EXPORTS
        #define SHURIKENLIB_API __declspec(dllexport)
    #else
        #define SHURIKENLIB_API __declspec(dllimport)
    #endif
#else
    #define SHURIKENLIB_API
#endif

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace shurikenapi {

    class IDexTypeInfo {
      public:
        virtual ~IDexTypeInfo() = default;
        IDexTypeInfo& operator=(IDexTypeInfo&&) = delete;
        virtual DexType getType() const = 0;
        virtual std::optional<FundamentalValue> getFundamentalValue() const = 0;
    };

    class IPrototype {
      public:
        virtual ~IPrototype() = default;
        IPrototype& operator=(IPrototype&&) = delete;
        virtual std::vector<std::reference_wrapper<const IDexTypeInfo>> getParameters() const = 0;
        virtual const IDexTypeInfo& getReturnType() const = 0;
        virtual const std::string& getString() const = 0;
    };

    class IClassMethod {
      public:
        virtual ~IClassMethod() = default;
        IClassMethod& operator=(IClassMethod&&) = delete;
        virtual const std::string& getName() const = 0;
        virtual const std::string& getDemangledName() const = 0;
        virtual const IPrototype& getPrototype() const = 0;
        virtual AccessFlags getFlags() const = 0;
        virtual std::span<uint8_t> getByteCode() const = 0;
    };

    class IClassField {
      public:
        virtual ~IClassField() = default;
        IClassField& operator=(IClassField&&) = delete;
        virtual const std::string& getName() const = 0;
        virtual AccessFlags getAccessFlags() const = 0;
        virtual const IDexTypeInfo& getFieldType() const = 0;
    };
    class IDexClass {
      public:
        virtual ~IDexClass() = default;
        IDexClass& operator=(IDexClass&&) = delete;
        virtual const std::string& getName() const = 0;
        virtual const std::string& getSuperClassName() const = 0;
        virtual const std::string& getSourceFileName() const = 0;
        virtual AccessFlags getAccessFlags() const = 0;
        virtual std::vector<std::reference_wrapper<const IClassField>> getStaticFields() const = 0;
        virtual std::vector<std::reference_wrapper<const IClassField>> getInstanceFields() const = 0;
        virtual std::vector<std::reference_wrapper<const IClassMethod>> getDirectMethods() const = 0;
        virtual std::vector<std::reference_wrapper<const IClassMethod>> getVirtualMethods() const = 0;
    };
    class IClassManager {
      public:
        virtual ~IClassManager() = default;
        IClassManager& operator=(IClassManager&&) = delete;
        virtual std::vector<std::reference_wrapper<const IDexClass>> getAllClasses() const = 0;
    };

    class IDex {
      public:
        virtual ~IDex() = default;
        IDex& operator=(IDex&&) = delete;
        virtual const DexHeader& getHeader() const = 0;
        virtual const IClassManager& getClassManager() const = 0;
    };

    SHURIKENLIB_API std::unique_ptr<IDex> parse_dex(const std::string& filePath);

    namespace utils {
        SHURIKENLIB_API std::string DexFlags2String(shurikenapi::AccessFlags ac);
        SHURIKENLIB_API std::string DexType2String(shurikenapi::DexType dexType);
        SHURIKENLIB_API std::string DexType2String(const shurikenapi::IDexTypeInfo& dexType);
        SHURIKENLIB_API std::string DexValue2String(shurikenapi::FundamentalValue dexType);
    } // namespace utils
} // namespace shurikenapi

#endif // SHURIKEN_CPP_CORE_H
