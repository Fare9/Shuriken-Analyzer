// Shuriken C++ Public API
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

    class IDex;
    /// @brief The main api function to parse a dex file.
    SHURIKENLIB_API std::unique_ptr<IDex> parse_dex(const std::string& filePath);

    class IDisassembler {
      public:
        virtual ~IDisassembler() = default;
        IDisassembler& operator=(IDisassembler&&) = delete;
        virtual void sayHello() const = 0;
    };

    /// @brief This class holds the information about a type in the dex file.
    class IDexTypeInfo {
      public:
        virtual ~IDexTypeInfo() = default;
        IDexTypeInfo& operator=(IDexTypeInfo&&) = delete;
        virtual DexType getType() const = 0;
        virtual std::optional<FundamentalValue> getFundamentalValue() const = 0;
    };

    /// @brief This class holds the information about a method's prototype.
    class IPrototype {
      public:
        virtual ~IPrototype() = default;
        IPrototype& operator=(IPrototype&&) = delete;
        virtual std::vector<std::reference_wrapper<const IDexTypeInfo>> getParameters() const = 0;
        virtual const IDexTypeInfo& getReturnType() const = 0;
        virtual const std::string& getString() const = 0;
    };

    /// @brief This class holds the information about a method in a class.
    class IClassMethod {
      public:
        virtual ~IClassMethod() = default;
        IClassMethod& operator=(IClassMethod&&) = delete;
        virtual const std::string& getName() const = 0;
        virtual const std::string& getDalvikName() const = 0;
        virtual const std::string& getDemangledName() const = 0;
        virtual const IPrototype& getPrototype() const = 0;
        virtual AccessFlags getFlags() const = 0;
        virtual std::span<uint8_t> getByteCode() const = 0;
        virtual std::uint64_t getCodeLocation() const = 0;
    };

    /// @brief This class holds the information about a field in a class.
    class IClassField {
      public:
        virtual ~IClassField() = default;
        IClassField& operator=(IClassField&&) = delete;
        virtual const std::string& getName() const = 0;
        virtual AccessFlags getAccessFlags() const = 0;
        virtual const IDexTypeInfo& getFieldType() const = 0;
    };

    /// @brief This class interface is responsible for holding all the information about an individual class in the dex file.
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

    /// @brief The class manager is responsible for holding all the classes in the dex file.
    class IClassManager {
      public:
        virtual ~IClassManager() = default;
        IClassManager& operator=(IClassManager&&) = delete;
        virtual std::vector<std::reference_wrapper<const IDexClass>> getAllClasses() const = 0;
    };

    /// @brief This is the main object that holds all the information about a parsed dex file.
    class IDex {
      public:
        virtual ~IDex() = default;
        IDex& operator=(IDex&&) = delete;
        virtual const DexHeader& getHeader() const = 0;
        virtual const IClassManager& getClassManager() const = 0;
        virtual const IDisassembler& getDisassembler() const = 0;
    };

    namespace utils {
        SHURIKENLIB_API std::string DexFlags2String(shurikenapi::AccessFlags ac);
        SHURIKENLIB_API std::string DexType2String(shurikenapi::DexType dexType);
        SHURIKENLIB_API std::string DexType2String(const shurikenapi::IDexTypeInfo& dexType);
        SHURIKENLIB_API std::string DexValue2String(shurikenapi::FundamentalValue dexType);
    } // namespace utils
} // namespace shurikenapi

#endif // SHURIKEN_CPP_CORE_H
