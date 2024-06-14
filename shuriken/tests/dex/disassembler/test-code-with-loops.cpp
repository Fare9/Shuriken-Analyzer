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
    // Existing methods...
    
    // Add a new method to test loops
    {"Lcom/dexbox/_loop;->test_loop()V", ".method public static Lcom/dexbox/_loop;->test_loop()V\n"
                                         ".registers 3\n"
                                         "00000000 const/4 v0, 0x0  // int:0\n"  // loop counter initialization
                                         ":loop_start\n"
                                         "00000002 sget-object v1, java.lang.System->out java.io.PrintStream // field@0\n"
                                         "00000006 int-to-string v2, v0\n"
                                         "0000000a invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4\n"
                                         "0000000e add-int/lit8 v0, v0, 0x1  // Increment counter\n"
                                         "00000012 const/16 v2, 0x64  // int:100\n"
                                         "00000014 if-lt v0, v2, :loop_start  // Loop back if counter < 100\n"
                                         "00000018 return-void\n"
                                         ".end method"}
};

int main() {
    std::string test_file = DEX_FILES_FOLDER "_exception.dex";
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

