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
#include <string>
#include <vector>

namespace shurikenapi {

    struct DexClass {
        ClassDef definitions;
        std::vector<ClassMethod> methods;
        std::vector<ClassField> fields;
    };

    class IClassManager {
      public:
        virtual ~IClassManager() = default;
        IClassManager& operator=(IClassManager&&) = delete;
        virtual const std::vector<DexClass>& getAllClasses() const = 0;
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
        SHURIKENLIB_API std::string get_types_as_string(shurikenapi::access_flags ac);
    }
} // namespace shurikenapi

#endif // SHURIKEN_CPP_CORE_H
