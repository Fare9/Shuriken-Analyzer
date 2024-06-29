#include "plugin.h"

namespace BinaryNinja {

DEXView::DEXView(BinaryView* data, bool parseOnly)
    : BinaryView("DEX", data->GetFile(), data), m_parseOnly(parseOnly) {
    CreateLogger("BinaryView");
    m_logger = CreateLogger("BinaryView.DEXView");
    m_backedByDatabase = data->GetFile()->IsBackedByDatabase("DEX");
}

bool DEXView::Init() {
    m_logger->LogError("DEXView::Init()");
    Ref<Settings> settings = GetLoadSettings(GetTypeName());
    Ref<Settings> viewSettings = Settings::Instance();

    const uint64_t alignment = 0x1000;
    const uint64_t rawFileOffset = 0;
    const uint64_t dexCodeSegmentSize = (GetParentView()->GetLength() + alignment - 1) & ~(alignment - 1);
    const uint64_t fieldDataSegmentAddress = m_imageBase + dexCodeSegmentSize;
    const uint64_t fieldDataSegmentSize = 0x1000;

    // TODO: create/use arch-dex
    m_arch = Architecture::GetByName("x86");
    m_platform = m_arch->GetStandalonePlatform();
    SetDefaultArchitecture(m_arch);
    SetDefaultPlatform(m_platform);

    // TODO: correct create memory segments
    AddAutoSegment(m_imageBase, GetParentView()->GetLength(), rawFileOffset, GetParentView()->GetLength(),
                   SegmentReadable);
    AddAutoSegment(fieldDataSegmentAddress, fieldDataSegmentSize, 0, 0x100, SegmentWritable);
    AddAutoSection("code", 0, dexCodeSegmentSize, ReadOnlyDataSectionSemantics);
    AddAutoSection("fields", fieldDataSegmentAddress, fieldDataSegmentSize, ReadWriteDataSectionSemantics);

    buildStructures();
    buildFunctions();

    return true;
}

// TODO: move to platform plugin
Ref<Type> DEXView::getFundamental(const shurikenapi::FundamentalValue& value) {
    switch (value) {
    case shurikenapi::FundamentalValue::kBoolean:
        return Type::BoolType();
    case shurikenapi::FundamentalValue::kByte:
        return Type::IntegerType(1, false);
    case shurikenapi::FundamentalValue::kChar:
        return Type::IntegerType(1, true);
    case shurikenapi::FundamentalValue::kDouble:
        return Type::FloatType(8);
    case shurikenapi::FundamentalValue::kFloat:
        return Type::FloatType(4);
    case shurikenapi::FundamentalValue::kInt:
        return GetTypeByName(QualifiedName("int"));
        //return Type::IntegerType(4, true);
    case shurikenapi::FundamentalValue::kLong:
        return Type::IntegerType(8, true);
    case shurikenapi::FundamentalValue::kShort:
        return Type::IntegerType(2, true);
    case shurikenapi::FundamentalValue::kVoid:
        return Type::VoidType();
    default:
        m_logger->LogWarn("Unknown fundamental value: %d", value);
        return Type::VoidType();
    }
}

int tmp = 0;
Ref<Function> DEXView::buildMethod(const shurikenapi::IClassMethod& method) {

    int funcOffset = method.getCodeLocation();
    m_logger->LogInfo("---------------");
    m_logger->LogInfo("Building method: %s at %016llx", method.getDalvikName().c_str(), funcOffset);

    // Get method prototype
    auto& prototype = method.getPrototype();
    auto& returnType = prototype.getReturnType();
    if (returnType.getType() != shurikenapi::DexType::kFundamental) {
        m_logger->LogError("Unsupported return type for method: %s", method.getDalvikName().c_str());
        return Ref<Function>();
    }
        
    // Create function object with calling convention
    Ref<Function> func = CreateUserFunction(m_platform, funcOffset);
    func->SetCallingConvention(m_platform->GetDefaultCallingConvention());

    // Create parameters
    std::vector<FunctionParameter> parameters;
    for (const auto& p : prototype.getParameters()) {
        if (p.get().getType() != shurikenapi::DexType::kFundamental) {
            m_logger->LogError("Unsupported parameter type for method: %s", method.getDalvikName().c_str());
            return Ref<Function>();
        }
        Ref<Type> paramType = getFundamental(p.get().getFundamentalValue().value());
        m_logger->LogInfo("ParameterType: %d", p.get().getFundamentalValue().value());
        parameters.push_back(FunctionParameter("", paramType));
    }
    
    // Set function type
    m_logger->LogInfo("ReturnType: %d", returnType.getFundamentalValue().value());
    Ref<Type> funcType = Type::FunctionType(Type::IntegerType(4, true), m_platform->GetDefaultCallingConvention(), parameters);
    func->SetUserType(funcType);

    // Define the function
    DefineUserSymbol(new Symbol(FunctionSymbol, method.getDalvikName(), funcOffset, NoBinding));


    m_logger->LogInfo("Building method: %s - OK", method.getDalvikName().c_str());

    return func;
}

void DEXView::buildFunctions() {

    // TODO: move to platform plugin
    DefineType("boolean", QualifiedName("boolean"),  Type::BoolType());
    DefineType("byte", QualifiedName("byte"),  Type::IntegerType(1, false));
    DefineType("char", QualifiedName("char"),  Type::IntegerType(1, true));
    DefineType("double", QualifiedName("double"),  Type::FloatType(8));
    DefineType("float", QualifiedName("float"),  Type::FloatType(4));
    DefineType("int", QualifiedName("int"),  Type::IntegerType(4, true));
    DefineType("long", QualifiedName("long"),  Type::IntegerType(8, true)); 
    DefineType("short", QualifiedName("short"),  Type::IntegerType(2, true));
    DefineType("void", QualifiedName("void"),  Type::VoidType());

    std::unique_ptr<shurikenapi::IDex> parsedDex = nullptr;
    try {
        parsedDex = shurikenapi::parse_dex(GetFile()->GetOriginalFilename());
    } catch (std::runtime_error& re) {
        m_logger->LogError("DEXView::buildFunctions() failed to parse symbols:", re.what());
    }

    auto classes = parsedDex->getClassManager().getAllClasses();
    int tmp = 0;
    for (const auto& c : classes) {
        m_logger->LogInfo("Class: %s", c.get().getName());
        auto component = CreateComponentWithName(c.get().getName());
        for (auto& m : c.get().getDirectMethods()) {
            Ref<Function> func = buildMethod(m.get());
            if (func) {
                component->AddFunction(func);
            }
        }
    }
}

void DEXView::buildStructures() {

    // TODO: move to platform plugin
    StructureBuilder dexHeaderBuilder;
    dexHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, true), 8), "magic");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "checksum");
    dexHeaderBuilder.AddMember(Type::ArrayType(Type::IntegerType(1, false), 20), "signature");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "file_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "header_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "endian_tag");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "link_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "link_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "map_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "string_ids_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "string_ids_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "type_ids_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "type_ids_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "proto_ids_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "proto_ids_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "field_ids_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "field_ids_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "method_ids_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "method_ids_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "class_defs_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "class_defs_off");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "data_size");
    dexHeaderBuilder.AddMember(Type::IntegerType(4, false), "data_off");
    Ref<Structure> dexHeaderStruct = dexHeaderBuilder.Finalize();

    Ref<Type> dexHeaderType = Type::StructureType(dexHeaderStruct);
    QualifiedName dexHeaderName = std::string("DEX_Header");
    QualifiedName dexHeaderTypeName =
        DefineType(Type::GenerateAutoTypeId("dex", dexHeaderName), dexHeaderName, dexHeaderType);
    DefineDataVariable(m_imageBase, Type::NamedType(this, dexHeaderTypeName));
    DefineAutoSymbol(new Symbol(DataSymbol, "__dex_header", m_imageBase, NoBinding));
}

uint64_t DEXView::PerformGetEntryPoint() const { return 0; }

size_t DEXView::PerformGetAddressSize() const { return 8; }

} // namespace BinaryNinja