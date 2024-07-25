//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file core-api-test-disassembler.cpp
// @brief test for the disassembler from the CORE API
// this API is the one that is used for doing bindings
// in other languages

#include "../../../include/shuriken/api/C/shuriken_core.h"
#include "dex-files-folder.inc"
#include <assert.h>
#include <iostream>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const char *file = DEX_FILES_FOLDER
        "DexParserTest.dex";

std::map<std::string, std::string> all_methods = {
        {"LDexParserTest;-><init>()V", R"(.method constructor public LDexParserTest;-><init>()V
.registers 2
00000000 invoke-direct {v1}, Ljava/lang/Object;-><init>()V // method@5
00000006 const/16 v0, 42
0000000a iput v0, v1, DexParserTest->field1 int // field@0
0000000e const-string v0, "Hello, Dex Parser!" // string@6
00000012 iput-object v0, v1, DexParserTest->field2 java.lang.String // field@1
00000016 return-void
.end method)"},

        {"LDexParserTest;->calculateSum(II)I", R"(.method private LDexParserTest;->calculateSum(II)I
.registers 7
00000000 add-int v0, v5, v6
00000004 sget-object v1, java.lang.System->out java.io.PrintStream // field@2
00000008 new-instance v2, Ljava/lang/StringBuilder; // type@5
0000000c invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V // method@6
00000012 const-string v3, "Sum of " // string@18
00000016 invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8
0000001c move-result-object v2
0000001e invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7
00000024 move-result-object v5
00000026 const-string v2, " and " // string@0
0000002a invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8
00000030 move-result-object v5
00000032 invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7
00000038 move-result-object v5
0000003a const-string v6, " is: " // string@1
0000003e invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8
00000044 move-result-object v5
00000046 invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7
0000004c move-result-object v5
0000004e invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9
00000054 move-result-object v5
00000056 invoke-virtual {v1, v5}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4
0000005c return v0
.end method)"},

        {"LDexParserTest;->main([Ljava/lang/String;)V", R"(.method public static LDexParserTest;->main([Ljava/lang/String;)V
.registers 3
00000000 new-instance v2, LDexParserTest; // type@1
00000004 invoke-direct {v2}, LDexParserTest;-><init>()V // method@0
0000000a invoke-direct {v2}, LDexParserTest;->printMessage()V // method@3
00000010 const/16 v0, 10
00000014 const/16 v1, 20
00000018 invoke-direct {v2, v0, v1}, LDexParserTest;->calculateSum(II)I // method@1
0000001e return-void
.end method)"},

        {"LDexParserTest;->printMessage()V", R"(.method private LDexParserTest;->printMessage()V
.registers 4
00000000 sget-object v0, java.lang.System->out java.io.PrintStream // field@2
00000004 new-instance v1, Ljava/lang/StringBuilder; // type@5
00000008 invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V // method@6
0000000e const-string v2, "Field 1: " // string@4
00000012 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8
00000018 move-result-object v1
0000001a iget v2, v3, DexParserTest->field1 int // field@0
0000001e invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7
00000024 move-result-object v1
00000026 invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9
0000002c move-result-object v1
0000002e invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4
00000034 sget-object v0, java.lang.System->out java.io.PrintStream // field@2
00000038 new-instance v1, Ljava/lang/StringBuilder; // type@5
0000003c invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V // method@6
00000042 const-string v2, "Field 2: " // string@5
00000046 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8
0000004c move-result-object v1
0000004e iget-object v2, v3, DexParserTest->field2 java.lang.String // field@1
00000052 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8
00000058 move-result-object v1
0000005a invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9
00000060 move-result-object v1
00000062 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4
00000068 sget-object v0, java.lang.System->out java.io.PrintStream // field@2
0000006c const-string v1, "This is a test message printed from DexParserTest class." // string@19
00000070 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4
00000076 return-void
.end method)"}};


void checkDisassembledMethod(hDexContext dexContext);

int main(int argc, char *argv[]) {
    hDexContext dexContext = parse_dex(file);
    disassemble_dex(dexContext);
    checkDisassembledMethod(dexContext);
    destroy_dex(dexContext);
    return 0;
}

void checkDisassembledMethod(hDexContext dexContext) {
    // Go through the list of classes and we will get the
    // methods
    size_t nr_of_classes = get_number_of_classes(dexContext);
    uint16_t i;
    for (i = 0; i < nr_of_classes; ++i) {
        auto class_ = get_class_by_id(dexContext, i);

        for (uint32_t j = 0; j < class_->direct_methods_size; j++) {
            auto dalvik_name = class_->direct_methods[j].dalvik_name;
            printf("Method to find: %s\n", dalvik_name);
            auto disassembled_method =
                    get_disassembled_method(dexContext, dalvik_name);
            assert(disassembled_method != nullptr && "Error, method not found in the disassembled methods.");
            assert(all_methods.contains(dalvik_name) && "Error that method does not exists in the test");
            assert(strcmp(all_methods[dalvik_name].c_str(), disassembled_method->method_string) == 0 && "Error disassembly does not match");
            printf("Disassembled method: \n%s\n", disassembled_method->method_string);
        }

        for (uint32_t j = 0; j < class_->virtual_methods_size; j++) {
            auto dalvik_name = class_->virtual_methods[j].dalvik_name;
            printf("Method to find: %s\n", dalvik_name);
            auto disassembled_method =
                    get_disassembled_method(dexContext, dalvik_name);
            assert(disassembled_method != nullptr && "Error, method not found in the disassembled methods.");
            assert(all_methods.contains(dalvik_name) && "Error that method does not exists in the test");
            assert(strcmp(all_methods[dalvik_name].c_str(), disassembled_method->method_string) == 0 && "Error disassembly does not match");
            printf("Disassembled method: \n%s\n", disassembled_method->method_string);
        }
    }
}