#include "dex_cpp_core_api_internal.h"
#include <set>

namespace shurikenapi {

    namespace details {

        ShurikenDex::ShurikenDex(const std::string& filePath) : m_parser{shuriken::parser::parse_dex(filePath)} {

            // on ShurikenDex destruction the disassembler will destruct first and discard the parser pointer,
            // afterwards ShurikenDex will destruct and free ownership of the parser pointer
            m_disassembler = std::make_unique<shuriken::disassembler::dex::Disassembler>(m_parser.get());

            // --Add Header
            memcpy(&m_header, &m_parser->get_header().get_dex_header(), sizeof(DexHeader));

            inferExternalClasses();

            // --Add Classes to ClassManager
            for (auto& c : m_parser->get_classes().get_classdefs()) {

                // --Create Class Entry
                // printf("ADD: %s\n", c->get_class_idx()->get_class_name().data());
                std::string className{c->get_class_idx()->get_class_name()};
                std::string superName{c->get_superclass() ? c->get_superclass()->get_class_name().data() : std::string{}};
                std::string sourceName{!c->get_source_file().empty() ? std::string(c->get_source_file()) : std::string{}};
                shurikenapi::AccessFlags accessFlags{static_cast<shurikenapi::AccessFlags>(c->get_access_flags())};
                auto classEntry = std::make_unique<details::ShurikenDexClass>(
                    c->get_raw_class_idx(), std::move(className), std::move(superName), std::move(sourceName), accessFlags);

                // --Process Fields
                shuriken::parser::dex::ClassDataItem& classDataItem = c->get_class_data_item();
                processFields(classDataItem, *classEntry.get());

                // --Process Methods
                for (size_t i = 0; i < c->get_class_data_item().get_number_of_direct_methods(); i++) {
                    auto data = c->get_class_data_item().get_direct_method_by_id(static_cast<std::uint32_t>(i));
                    classEntry->addDirectMethod(std::move(processMethods(data)));
                }
                for (size_t i = 0; i < c->get_class_data_item().get_number_of_virtual_methods(); i++) {
                    auto data = c->get_class_data_item().get_virtual_method_by_id(static_cast<std::uint32_t>(i));
                    classEntry->addVirtualMethod(std::move(processMethods(data)));
                }

                // --Add the Class into the ClassManager
                m_classManager.addClass(std::move(classEntry));
            }
        }

        void ShurikenDex::inferExternalClasses() {

            std::vector<uint32_t> classInDex;
            for (auto& c : m_parser->get_classes().get_classdefs()) {
                classInDex.push_back(c->get_raw_class_idx());
            }

            std::vector<details::ShurikenDexClass*> externalClasses;

            for (const auto& m : m_parser->get_methods().get_methods_const()) {

                // Is the class external?
                if (std::find(classInDex.begin(), classInDex.end(), m->get_raw_class_id()) != classInDex.end())
                    continue; // no

                // do we know this class ?
                details::ShurikenDexClass* externalClass = nullptr;
                auto classEntry = std::find_if(externalClasses.begin(), externalClasses.end(),
                                               [&](details::ShurikenDexClass* c) { return c->getClassId() == m->get_raw_class_id(); });

                if (classEntry == externalClasses.end()) {
                    auto newClass = new details::ShurikenDexClass(m->get_raw_class_id(), std::string(m->get_class()->get_raw_type()),
                                                                  "", "", shurikenapi::AccessFlags::NONE);

                    externalClasses.push_back(newClass);
                    externalClass = newClass;
                } else {
                    externalClass = *classEntry;
                }

                std::string namePlain{m->get_method_name()};
                std::string nameDalvik{m->get_class()->get_raw_type()};
                nameDalvik += "->";
                nameDalvik += m->get_method_name();
                nameDalvik += m->get_prototype()->get_dalvik_prototype();

                printf("1: Add Method: %d --> %s - %s - %s\n", m->get_raw_method_id(), namePlain.c_str(), nameDalvik.c_str(), nameDalvik.c_str());
                auto methodEntry =
                    std::make_unique<details::ShurikenClassMethod>(m->get_raw_method_id(), namePlain, nameDalvik, "", nullptr,
                                                                   shurikenapi::AccessFlags::NONE, std::span<uint8_t>{}, -1);

                externalClass->addExternalMethod(std::move(methodEntry));
                externalClass->setExternal();
            }
            for (auto& c : externalClasses) {
                m_classManager.addClass(std::unique_ptr<details::ShurikenDexClass>(c));
            }
        }

        void ShurikenDex::processFields(shuriken::parser::dex::ClassDataItem& classDataItem, details::ShurikenDexClass& classEntry) {

            for (size_t i = 0; i < classDataItem.get_number_of_instance_fields(); i++) {
                auto data = classDataItem.get_instance_field_by_id(static_cast<std::uint32_t>(i));

                classEntry.addInstanceField(std::move(createFieldEntry(data)));
            }
            for (size_t i = 0; i < classDataItem.get_number_of_static_fields(); i++) {
                auto data = classDataItem.get_static_field_by_id(static_cast<std::uint32_t>(i));

                classEntry.addStaticField(std::move(createFieldEntry(data)));
            }
        }

        std::unique_ptr<details::ShurikenClassField> ShurikenDex::createFieldEntry(shuriken::parser::dex::EncodedField* data) {

            std::string fieldName{data->get_field()->field_name().data()};
            shurikenapi::AccessFlags fieldFlags{static_cast<shurikenapi::AccessFlags>(data->get_flags())};
            std::unique_ptr<IDexTypeInfo> fieldType = createTypeInfo(data->get_field()->field_type());

            return std::make_unique<details::ShurikenClassField>(std::move(fieldName), std::move(fieldFlags), std::move(fieldType));
        }

        std::unique_ptr<IClassMethod> ShurikenDex::processMethods(shuriken::parser::dex::EncodedMethod* data) {

            // --Set Method Name
            std::uint32_t methodId = data->getMethodID()->get_raw_method_id();

            std::string name{data->getMethodID()->get_method_name()};
            std::string dalvikName{data->getMethodID()->dalvik_name_format()};
            std::string demangledName{data->getMethodID()->demangle()};

            // --Create Method Prototype
            std::string prototypeString{data->getMethodID()->get_prototype()->get_dalvik_prototype()};
            std::unique_ptr<IDexTypeInfo> returnType = createTypeInfo(data->getMethodID()->get_prototype()->get_return_type());
            std::vector<std::unique_ptr<IDexTypeInfo>> parameters;
            for (const auto& p : data->getMethodID()->get_prototype()->get_parameters()) {
                auto paramEntry = createTypeInfo(p);
                parameters.push_back(std::move(paramEntry));
            }
            std::unique_ptr<IPrototype> prototypeEntry =
                std::make_unique<details::ShurikenPrototype>(std::move(prototypeString), std::move(returnType), std::move(parameters));

            // --Set Flags and ByteCode
            shurikenapi::AccessFlags flags{static_cast<shurikenapi::AccessFlags>(data->get_flags())};
            std::span<uint8_t> byteCode{data->get_code_item()->get_bytecode()};
            std::uint64_t codeLocation = data->get_code_location();

            printf("2: Add Method: %d --> %s - %s - %s\n", methodId, name.c_str(), dalvikName.c_str(), demangledName.c_str());
            return std::make_unique<details::ShurikenClassMethod>(methodId, std::move(name), std::move(dalvikName),
                                                                  std::move(demangledName), std::move(prototypeEntry), flags, byteCode,
                                                                  codeLocation);
        }

        std::unique_ptr<IDexTypeInfo> ShurikenDex::createTypeInfo(shuriken::parser::dex::DVMType* rawType) {
            auto output = std::make_unique<DexTypeInfo>();

            switch (rawType->get_type()) {
                case shuriken::parser::dex::FUNDAMENTAL: {
                    auto dvmType = dynamic_cast<shuriken::parser::dex::DVMFundamental*>(rawType);
                    output->setType(DexType::kFundamental);
                    output->setFundamentalValue(static_cast<FundamentalValue>(dvmType->get_fundamental_type()));
                    break;
                }
                case shuriken::parser::dex::CLASS: {
                    output->setType(DexType::kClass);
                    break;
                }
                case shuriken::parser::dex::ARRAY: {
                    output->setType(DexType::kArray);
                    break;
                }
                default:
                    throw std::runtime_error("Error, not a supported type...");
            }

            return output;
        }

        const DexHeader& ShurikenDex::getHeader() const {
            return m_header;
        }

        const IClassManager& ShurikenDex::getClassManager() const {
            return m_classManager;
        };

        const IDisassembler& ShurikenDex::getDisassembler() const {
            return static_cast<const IDisassembler&>(*this);
        }

    } // namespace details

} // namespace shurikenapi