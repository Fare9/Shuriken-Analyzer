#ifndef SHURIKEN_CPP_CORE_INTERNAL_H
#define SHURIKEN_CPP_CORE_INTERNAL_H

#include "shuriken/shuriken_cpp_core.h"

#include "dex_cpp_core_api_internal.h"
#include "shuriken/parser/shuriken_parsers.h"
#include <memory>
#include <string>

namespace shurikenapi {
    namespace details {

        class ShurikenClassManager : public IClassManager {
          public:
            const std::vector<DexClass>& getAllClasses() const override;
            void addClass(DexClass&& entry);

          private:
            std::vector<DexClass> m_classes;
        };

        class ShurikenDex : public IDex {
          public:
            ShurikenDex(const std::string& filePath);
            const DexHeader& getHeader() const override;
            const IClassManager& getClassManager() const override;

          private:
            void fillField(ClassField* fieldEntry, shuriken::parser::dex::EncodedField* data);

            std::unique_ptr<shuriken::parser::dex::Parser> m_parser;
            ShurikenClassManager m_classManager;
            DexHeader m_header;
        };

    } // namespace details
} // namespace shurikenapi

#endif // SHURIKEN_CPP_CORE_INTERNAL_H