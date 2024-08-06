//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file test-code-with-exceptions.cpp
// @brief Test for the disassembler, test code with exceptions

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
        {"Lcom/dexbox/_exception;->test_nest()V", ".method private static Lcom/dexbox/_exception;->test_nest()V\n"
                                                  ".registers 2\n"
                                                  ".try_start_0\n"
                                                  "00000000 sget-object v0, java.lang.System->out java.io.PrintStream // field@0\n"
                                                  "00000004 const-string v1, \"throw 1: ..\" // string@23\n"
                                                  "00000008 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                  "0000000e new-instance v0, Ljava/lang/NullPointerException; // type@3\n"
                                                  "00000012 invoke-direct {v0}, Ljava/lang/NullPointerException;-><init>()V // method@5\n"
                                                  "00000018 throw v0\n"
                                                  ".try_end_d\n"
                                                  ".catch Ljava/lang/NullPointerException; {.try_start_0 .. .try_end_d} :catch_f\n"
                                                  ".catch Ljava/lang/RuntimeException; {.try_start_0 .. .try_end_d} :catch_d\n"
                                                  ":catch_d\n"
                                                  "0000001a move-exception v0\n"
                                                  "0000001c goto 0x48 // +0x22\n"
                                                  ":catch_f\n"
                                                  "0000001e move-exception v0\n"
                                                  ".try_start_10\n"
                                                  "00000020 sget-object v0, java.lang.System->out java.io.PrintStream // field@0\n"
                                                  "00000024 const-string v1, \"throw 1: ok\" // string@24\n"
                                                  "00000028 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                  "0000002e sget-object v0, java.lang.System->out java.io.PrintStream // field@0\n"
                                                  "00000032 const-string v1, \"throw 2: ..\" // string@25\n"
                                                  "00000036 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                  "0000003c new-instance v0, Ljava/lang/RuntimeException; // type@5\n"
                                                  "00000040 invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V // method@7\n"
                                                  "00000046 throw v0\n"
                                                  ".try_end_24\n"
                                                  ".catch Ljava/lang/RuntimeException; {.try_start_10 .. .try_end_24} :catch_d\n"
                                                  "00000048 sget-object v0, java.lang.System->out java.io.PrintStream // field@0\n"
                                                  "0000004c const-string v1, \"throw 2: ok\" // string@26\n"
                                                  "00000050 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                  "00000056 return-void\n"
                                                  ".end method"},
        {"Lcom/dexbox/_exception;->test_throw()V", ".method private static Lcom/dexbox/_exception;->test_throw()V\n"
                                                   ".registers 3\n"
                                                   "00000000 const-string v0, \"throw: finally\" // string@28\n"
                                                   ".try_start_2\n"
                                                   "00000004 sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                   "00000008 const-string v2, \"throw: ..\" // string@27\n"
                                                   "0000000c invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                   "00000012 new-instance v1, Ljava/lang/NullPointerException; // type@3\n"
                                                   "00000016 invoke-direct {v1}, Ljava/lang/NullPointerException;-><init>()V // method@5\n"
                                                   "0000001c throw v1\n"
                                                   ".try_end_f\n"
                                                   ".catch Ljava/lang/NullPointerException; {.try_start_2 .. .try_end_f} :catch_11\n"
                                                   "0000001e move-exception v1\n"
                                                   "00000020 goto 0x40 // +0x16\n"
                                                   ":catch_11\n"
                                                   "00000022 move-exception v1\n"
                                                   ".try_start_12\n"
                                                   "00000024 sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                   "00000028 const-string v2, \"throw: ok\" // string@29\n"
                                                   "0000002c invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                   ".try_end_19\n"
                                                   "00000032 sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                                   "00000036 invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                   "0000003c nop\n"
                                                   "0000003e return-void\n"
                                                   "00000040 sget-object v2, java.lang.System->out java.io.PrintStream // field@0\n"
                                                   "00000044 invoke-virtual {v2, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                                   "0000004a throw v1\n"
                                                   ".end method"}};

int main() {

    std::string test_file = DEX_FILES_FOLDER
            "_exception.dex";

    std::unique_ptr<shuriken::parser::dex::Parser> dex_parser = nullptr;
    std::unique_ptr<shuriken::disassembler::dex::DexDisassembler> dex_disassembler = nullptr;

    dex_parser = shuriken::parser::parse_dex(test_file);
    dex_disassembler = std::make_unique<shuriken::disassembler::dex::DexDisassembler>(dex_parser.get());
    dex_disassembler->disassembly_dex();

    for (auto disassembled_method: disassembled_methods) {
        // TODO: A getter so i'm not sure if we should store it inside method
        [[maybe_unused]] auto method = dex_disassembler->get_disassembled_method(disassembled_method.first);
        std::cout << disassembled_method.first << " check\n";
        assert(strcmp(disassembled_method.second.data(), method->print_method(true).data()) == 0 && "Error, the method has not been properly disassembled");
        std::cout << disassembled_method.first << " correct\n";
    }

    return 0;
}
