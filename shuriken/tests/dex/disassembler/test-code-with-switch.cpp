//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file test-code-with-switch.cpp
// @brief Test for the disassembler, test code with switch statement

#include "dex-files-folder.inc"
#include "shuriken/disassembler/Dex/dex_disassembler.h"
#include "shuriken/parser/Dex/parser.h"
#include "shuriken/parser/shuriken_parsers.h"

#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

std::unordered_map<std::string, std::string_view> disassembled_methods = {
        {"Lcom/dexbox/_switch;->performAction(I)V", ".method public static Lcom/dexbox/_switch;->performAction(I)V\n"
                                                    ".registers 2\n"
                                                    "00000000 packed-switch v1, 136\n"
                                                    "00000006 sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "0000000a const-string v0, \"Invalid choice\" // string@2\n"
                                                    "0000000e invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "00000014 goto/16 0x10c // +0x124\n"
                                                    "00000018 sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "0000001c const-string v0, \"Performing action 15\" // string@14\n"
                                                    "00000020 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "00000026 goto/16 0x10c // +0x115\n"
                                                    "0000002a sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "0000002e const-string v0, \"Performing action 14\" // string@13\n"
                                                    "00000032 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "00000038 goto/16 0x10c // +0x106\n"
                                                    "0000003c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000040 const-string v0, \"Performing action 13\" // string@12\n"
                                                    "00000044 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000004a goto 0x10c // +0x97\n"
                                                    "0000004c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000050 const-string v0, \"Performing action 12\" // string@11\n"
                                                    "00000054 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000005a goto 0x10c // +0x89\n"
                                                    "0000005c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000060 const-string v0, \"Performing action 11\" // string@10\n"
                                                    "00000064 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000006a goto 0x10c // +0x81\n"
                                                    "0000006c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000070 const-string v0, \"Performing action 10\" // string@9\n"
                                                    "00000074 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000007a goto 0x10c // +0x73\n"
                                                    "0000007c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000080 const-string v0, \"Performing action 9\" // string@22\n"
                                                    "00000084 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000008a goto 0x10c // +0x65\n"
                                                    "0000008c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000090 const-string v0, \"Performing action 8\" // string@21\n"
                                                    "00000094 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000009a goto 0x10c // +0x57\n"
                                                    "0000009c sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "000000a0 const-string v0, \"Performing action 7\" // string@20\n"
                                                    "000000a4 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "000000aa goto 0x10c // +0x49\n"
                                                    "000000ac sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "000000b0 const-string v0, \"Performing action 6\" // string@19\n"
                                                    "000000b4 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "000000ba goto 0x10c // +0x41\n"
                                                    "000000bc sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "000000c0 const-string v0, \"Performing action 5\" // string@18\n"
                                                    "000000c4 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "000000ca goto 0x10c // +0x33\n"
                                                    "000000cc sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "000000d0 const-string v0, \"Performing action 4\" // string@17\n"
                                                    "000000d4 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "000000da goto 0x10c // +0x25\n"
                                                    "000000dc sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "000000e0 const-string v0, \"Performing action 3\" // string@16\n"
                                                    "000000e4 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "000000ea goto 0x10c // +0x17\n"
                                                    "000000ec sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "000000f0 const-string v0, \"Performing action 2\" // string@15\n"
                                                    "000000f4 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "000000fa goto 0x10c // +0x9\n"
                                                    "000000fc sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                    "00000100 const-string v0, \"Performing action 1\" // string@8\n"
                                                    "00000104 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@3\n"
                                                    "0000010a nop\n"
                                                    "0000010c return-void\n"
                                                    "0000010e nop\n"
                                                    "00000110 packed-switch-payload (size)15 (first/last key)1[0x7e,0x76,0x6e,0x66,0x5e,0x56,0x4e,0x46,0x3e,0x36,0x2e,0x26,0x1e,0x15,0xc]\n"
                                                    ".end method"}};

int main() {

    std::string test_file = DEX_FILES_FOLDER
            "_switch.dex";

    std::unique_ptr<shuriken::parser::dex::Parser> dex_parser = nullptr;
    std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> dex_disassembler = nullptr;

    dex_parser = shuriken::parser::parse_dex(test_file);
    dex_disassembler = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(dex_parser.get());
    dex_disassembler->disassembly_dex();

    for (auto disassembled_method: disassembled_methods) {
        auto method = dex_disassembler->get_disassembled_method(disassembled_method.first);
        std::cout << disassembled_method.first << " check\n";
        assert(strcmp(disassembled_method.second.data(), method->print_method(true).data()) == 0 && "Error, the method has not been properly disassembled");
        std::cout << disassembled_method.first << " correct\n";
    }

    return 0;
}