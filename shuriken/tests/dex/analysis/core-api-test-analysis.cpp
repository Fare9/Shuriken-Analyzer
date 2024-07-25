//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file core-api-test.cpp
// @brief A test for the analysis classes from the CORE API

#include "../../../include/shuriken/api/C/shuriken_core.h"
#include "dex-files-folder.inc"
#include <assert.h>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unordered_map>
#include <vector>

const char *file = DEX_FILES_FOLDER
        "DexParserTest.dex";

std::unordered_map<std::string, std::vector<std::string>> methods = {
        {"LDexParserTest;->printMessage()V",
         {R"(BB.0-120
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
)"}},
        {"LDexParserTest;->main([Ljava/lang/String;)V",
         {R"(BB.0-32
00000000 new-instance v2, LDexParserTest; // type@1
00000004 invoke-direct {v2}, LDexParserTest;-><init>()V // method@0
0000000a invoke-direct {v2}, LDexParserTest;->printMessage()V // method@3
00000010 const/16 v0, 10
00000014 const/16 v1, 20
00000018 invoke-direct {v2, v0, v1}, LDexParserTest;->calculateSum(II)I // method@1
0000001e return-void
)"}},
        {"LDexParserTest;->calculateSum(II)I",
         {R"(BB.0-94
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
)"}},
        {"LDexParserTest;-><init>()V",
         {R"(BB.0-24
00000000 invoke-direct {v1}, Ljava/lang/Object;-><init>()V // method@5
00000006 const/16 v0, 42
0000000a iput v0, v1, DexParserTest->field1 int // field@0
0000000e const-string v0, "Hello, Dex Parser!" // string@6
00000012 iput-object v0, v1, DexParserTest->field2 java.lang.String // field@1
00000016 return-void
)"}}};

void check_analysis_classes(hDexContext dexContext);

int main(int argc, char *argv[]) {
    hDexContext dexContext = parse_dex(file);
    disassemble_dex(dexContext);
    create_dex_analysis(dexContext, true);
    analyze_classes(dexContext);
    check_analysis_classes(dexContext);
    destroy_dex(dexContext);
    return 0;
}

void check_analysis_classes(hDexContext dexContext) {
    size_t nr_of_classes = get_number_of_classes(dexContext);
    uint16_t i;
    for (i = 0; i < nr_of_classes; ++i) {
        auto class_ = get_class_by_id(dexContext, i);
        auto name = class_->class_name;
        auto class_analysis = get_analyzed_class(dexContext, name);
        assert(class_analysis != nullptr && "Error, class was not found.");

        for (uint32_t j = 0; j < class_analysis->n_of_methods; j++) {
            auto method_analysis = class_analysis->methods[j];
            printf("%s\n", method_analysis->full_name);
            auto basic_blocks = method_analysis->basic_blocks;
            for (uint32_t z = 0; z < basic_blocks->n_of_blocks; z++) {
                auto basic_block = basic_blocks->blocks[z];
                printf("%s\n", basic_block.block_string);
                auto data = methods[method_analysis->full_name][z].data();
                assert(strcmp(data, basic_block.block_string) == 0 && "Error, basic block disassembly is not correct");
            }
        }
    }
}
