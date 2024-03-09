#include "dex_cpp_core_api_internal.h"

namespace shurikenapi {

    // --Main API Function----
    SHURIKENLIB_API std::unique_ptr<IDex> parse_dex(const std::string& filePath) {
        std::unique_ptr<IDex> output = std::make_unique<details::ShurikenDex>(filePath);
        return output;
    }

    namespace details {

        // -- Initalisation----
        ShurikenDex::ShurikenDex(const std::string& filePath) {
            m_parser = shuriken::parser::parse_dex(filePath);

            for (auto& c : m_parser->get_classes().get_classdefs()) {
                auto classEntry = std::make_unique<details::DexClass>();

                classEntry->setName(std::string(c->get_class_idx()->get_class_name()));
                classEntry->setSuperClassName(c->get_superclass() ? c->get_superclass()->get_class_name().data() : "");
                classEntry->setSourceFileName(!c->get_source_file().empty() ? std::string(c->get_source_file()) : "");
                classEntry->setAccessFlags(static_cast<shurikenapi::AccessFlags>(c->get_access_flags()));

                for (size_t i = 0; i < c->get_class_data_item().get_number_of_instance_fields(); i++) {
                    auto data = c->get_class_data_item().get_instance_field_by_id(static_cast<std::uint32_t>(i));

                    auto fieldEntry = std::make_unique<details::ClassField>();
                    createFieldEntry(data, fieldEntry.get());
                    classEntry->addInstanceField(std::move(fieldEntry));
                }
                for (size_t i = 0; i < c->get_class_data_item().get_number_of_static_fields(); i++) {
                    auto data = c->get_class_data_item().get_static_field_by_id(static_cast<std::uint32_t>(i));

                    auto fieldEntry = std::make_unique<details::ClassField>();
                    createFieldEntry(data, fieldEntry.get());
                    classEntry->addStaticField(std::move(fieldEntry));
                }

                for (size_t i = 0; i < c->get_class_data_item().get_number_of_direct_methods(); i++) {
                    auto methodEntry = std::make_unique<details::ClassMethod>();
                    shuriken::parser::dex::EncodedMethod* data =
                        c->get_class_data_item().get_direct_method_by_id(static_cast<std::uint32_t>(i));

                    // --Set Method Name
                    methodEntry->setName(std::string(data->getMethodID()->get_method_name()));
                    methodEntry->setDemangledName(std::string(data->getMethodID()->demangle()));

                    // --Create Method Prototype
                    auto prototypeEntry = std::make_unique<details::Prototype>();
                    prototypeEntry->setString(std::string(data->getMethodID()->get_prototype()->get_dalvik_prototype()));
                    prototypeEntry->setReturnType(createTypeInfo(data->getMethodID()->get_prototype()->get_return_type()));
                    for (const auto& p : data->getMethodID()->get_prototype()->get_parameters()) {
                        auto paramEntry = createTypeInfo(p);
                        prototypeEntry->addParameter(std::move(paramEntry));
                    }
                    methodEntry->setPrototype(std::move(prototypeEntry));

                    // --Set Flags and ByteCode
                    methodEntry->setFlags(static_cast<shurikenapi::AccessFlags>(data->get_flags()));
                    methodEntry->setByteCode(data->get_code_item()->get_bytecode());

                    // --Add Method into the current Class
                    classEntry->addDirectMethod(std::move(methodEntry));
                }

                // --Add the Class into the ClassManager
                m_classManager.addClass(std::move(classEntry));
            }

            // --Add Header
            shuriken::parser::dex::DexHeader::dexheader_t& out = m_parser->get_header().get_dex_header();
            memcpy(&m_header, &out, sizeof(DexHeader));
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

        void ShurikenDex::createFieldEntry(shuriken::parser::dex::EncodedField* data, details::ClassField* fieldEntry) {

            fieldEntry->setName(data->get_field()->field_name().data());
            fieldEntry->setAccessFlags(static_cast<shurikenapi::AccessFlags>(data->get_flags()));
            fieldEntry->setFieldType(createTypeInfo(data->get_field()->field_type()));
        }

        // --Headers----
        const DexHeader& ShurikenDex::getHeader() const {
            return m_header;
        }

        // --Class Manager-----
        const IClassManager& ShurikenDex::getClassManager() const {
            return m_classManager;
        };

        void ShurikenClassManager::addClass(std::unique_ptr<IDexClass> entry) {
            m_classes.push_back(std::move(entry));
        }

        std::vector<std::reference_wrapper<const IDexClass>> ShurikenClassManager::getAllClasses() const {
            std::vector<std::reference_wrapper<const IDexClass>> classRefs;
            for (const auto& entry : m_classes) {
                classRefs.push_back(std::cref(*entry));
            }
            return classRefs;
        };

    } // namespace details

} // namespace shurikenapi