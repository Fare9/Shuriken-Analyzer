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
           
            // --Fill ClassManager----
            for (auto& c : m_parser->get_classes().get_classdefs()) {
                DexClass entry;

                // --Add Definition----
                auto class_idx = c->get_class_idx();
                auto super_class = c->get_superclass();
                auto& class_data_item = c->get_class_data_item();
                entry.definitions.class_name = c->get_class_idx()->get_class_name();
                entry.definitions.super_class = super_class ? super_class->get_class_name().data() : "";
                entry.definitions.source_file = !c->get_source_file().empty() ? c->get_source_file() : "";
                entry.definitions.flags = static_cast<shurikenapi::access_flags>(c->get_access_flags());
                size_t direct_methods_size = class_data_item.get_number_of_direct_methods();
                size_t virtual_methods_size = class_data_item.get_number_of_virtual_methods();
                size_t instance_fields_size = class_data_item.get_number_of_instance_fields();
                size_t static_fields_size = class_data_item.get_number_of_static_fields();

                // --Add Methods----
                for (size_t i = 0; i < virtual_methods_size; i++) {
                    ClassMethod classMethodEntry;
                    shuriken::parser::dex::EncodedMethod* data =
                        class_data_item.get_virtual_method_by_id(static_cast<std::uint32_t>(i));
                    classMethodEntry.name = data->getMethodID()->get_method_name();
                    classMethodEntry.prototype = data->getMethodID()->get_prototype()->get_dalvik_prototype();
                    classMethodEntry.flags = static_cast<shurikenapi::access_flags>(data->get_flags());
                    classMethodEntry.code_size = data->get_code_item()->get_bytecode().size();
                    classMethodEntry.code = data->get_code_item()->get_bytecode();
                    classMethodEntry.dalvik_name = data->getMethodID()->dalvik_name_format();
                    classMethodEntry.demangled_name = data->getMethodID()->demangle();
                    classMethodEntry.isVirtual = true;
                    classMethodEntry.isDirect = false;
                    entry.methods.push_back(std::move(classMethodEntry));
                }
                for (size_t i = 0; i < direct_methods_size; i++) {
                    ClassMethod classMethodEntry;
                    shuriken::parser::dex::EncodedMethod* data =
                        class_data_item.get_direct_method_by_id(static_cast<std::uint32_t>(i));
                    classMethodEntry.name = data->getMethodID()->get_method_name();
                    classMethodEntry.prototype = data->getMethodID()->get_prototype()->get_dalvik_prototype();
                    classMethodEntry.flags = static_cast<shurikenapi::access_flags>(data->get_flags());
                    classMethodEntry.code_size = data->get_code_item()->get_bytecode().size();
                    classMethodEntry.code = data->get_code_item()->get_bytecode();
                    classMethodEntry.dalvik_name = data->getMethodID()->dalvik_name_format();
                    classMethodEntry.demangled_name = data->getMethodID()->demangle();
                    classMethodEntry.isVirtual = false;
                    classMethodEntry.isDirect = true;
                    entry.methods.push_back(std::move(classMethodEntry));
                }

                // --Add Fields----
                for (size_t i = 0; i < instance_fields_size; i++) {
                    auto data = class_data_item.get_instance_field_by_id(static_cast<std::uint32_t>(i));
                    ClassField fieldEntry;
                    fillField(&fieldEntry, data);
                    fieldEntry.isInstance = true;
                    fieldEntry.isStatic = false;
                    entry.fields.push_back(std::move(fieldEntry));
                }
                for (size_t i = 0; i < static_fields_size; i++) {
                    auto data = class_data_item.get_static_field_by_id(static_cast<std::uint32_t>(i));
                    ClassField fieldEntry;
                    fillField(&fieldEntry, data);
                    fieldEntry.isInstance = false;
                    fieldEntry.isStatic = true;
                    entry.fields.push_back(std::move(fieldEntry));
                }

                m_classManager.addClass(std::move(entry));
            }

            shuriken::parser::dex::DexHeader::dexheader_t& out = m_parser->get_header().get_dex_header();
            memcpy(&m_header, &out, sizeof(DexHeader));
        }

        void ShurikenDex::fillField(ClassField* fieldEntry, shuriken::parser::dex::EncodedField* data) {

            auto field_id = data->get_field();
            auto field_type = field_id->field_type();
            auto type = field_type->get_type();

            fieldEntry->name = field_id->field_name().data();
            fieldEntry->flags = static_cast<shurikenapi::access_flags>(data->get_flags());
            fieldEntry->type_value = field_id->field_type()->get_raw_type();
            fieldEntry->fundamental_value = FundamentalValue::kNone;

            auto fundamental = dynamic_cast<shuriken::parser::dex::DVMFundamental*>(field_type);
            switch (type) {
                case shuriken::parser::dex::FUNDAMENTAL: {
                    fieldEntry->fundamental_type = DexType::kFundamental;
                    fieldEntry->fundamental_value = static_cast<FundamentalValue>(fundamental->get_type());
                    break;
                }
                case shuriken::parser::dex::CLASS: {
                    fieldEntry->fundamental_type = DexType::kClass;
                    break;
                }
                case shuriken::parser::dex::ARRAY: {
                    fieldEntry->fundamental_type = DexType::kArray;
                    auto array = reinterpret_cast<shuriken::parser::dex::DVMArray*>(field_type);
                    if (array->get_array_base_type()->get_type() == shuriken::parser::dex::FUNDAMENTAL) {
                        const auto fundamental =
                            reinterpret_cast<const shuriken::parser::dex::DVMFundamental*>(array->get_array_base_type());
                        fieldEntry->fundamental_value = static_cast<FundamentalValue>(fundamental->get_fundamental_type());
                    }
                    break;
                }
                default:
                    throw std::runtime_error("Error, not supported type...");
            }
        }

        // --Headers----
        const DexHeader& ShurikenDex::getHeader() const {
            return m_header;
        }

        // --Class Manager-----
        const IClassManager& ShurikenDex::getClassManager() const {
            return m_classManager;
        };

        void ShurikenClassManager::addClass(DexClass&& entry) {
            m_classes.push_back(entry);
        }

        const std::vector<DexClass>& ShurikenClassManager::getAllClasses() const {
            return m_classes;
        };



    } // namespace details

} // namespace shurikenapi