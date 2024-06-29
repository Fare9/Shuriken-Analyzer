#include "plugin.h"

namespace BinaryNinja {

DEXView::DEXView(BinaryView* data, bool parseOnly) : BinaryView("DEX", data->GetFile(), data), m_parseOnly(parseOnly) {
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

    AddAutoSegment(m_imageBase, GetParentView()->GetLength(), rawFileOffset, GetParentView()->GetLength(), SegmentReadable);
    AddAutoSegment(fieldDataSegmentAddress, fieldDataSegmentSize, 0, 0x100, SegmentWritable);
    AddAutoSection("code", 0, dexCodeSegmentSize, ReadOnlyDataSectionSemantics);
    AddAutoSection("fields", fieldDataSegmentAddress, fieldDataSegmentSize, ReadWriteDataSectionSemantics);

    buildStructures();
    buildFunctions();

    return true;
}

void DEXView::buildFunctions() {
    
/*
    std::unique_ptr<DataReader> shurikenReader = std::make_unique<DataReader>(GetParentView());
    shurikenapi::parse_dex(shurikenReader.get());
*/

    /* Sample Add Function
    auto cc = m_platform->GetDefaultCallingConvention();
    auto functionPointer = Type::PointerType(m_platform->GetArchitecture(), Type::FunctionType(Type::VoidType(), cc, {}));

    auto exampleFunctionType = Type::FunctionType(Type::VoidType(), cc, {FunctionParameter("", functionPointer)});
    auto funcType = Type::PointerType(m_platform->GetArchitecture(), exampleFunctionType);
    DefineAutoSymbolAndVariableOrFunction(GetDefaultPlatform(), new Symbol(FunctionSymbol, "func01", 0x200, NoBinding), funcType);
    */
}

void DEXView::buildStructures() {

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
    QualifiedName dexHeaderTypeName = DefineType(Type::GenerateAutoTypeId("dex", dexHeaderName), dexHeaderName, dexHeaderType);
    DefineDataVariable(m_imageBase, Type::NamedType(this, dexHeaderTypeName));
    DefineAutoSymbol(new Symbol(DataSymbol, "__dex_header", m_imageBase, NoBinding));
}

uint64_t DEXView::PerformGetEntryPoint() const { return 0; }

size_t DEXView::PerformGetAddressSize() const { return 8; }

} // namespace BinaryNinja