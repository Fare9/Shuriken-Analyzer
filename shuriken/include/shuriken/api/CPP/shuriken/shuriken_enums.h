#include <string>
#include <unordered_map>

#define CPPAPI 1

// TODO: these def includes should really be isolated next to the
// the other cpp-api ones to allow an easy distribution of minimal
// headers along with the library
namespace shurikenapi {
    namespace disassembly {

        enum class Mnemonic {
#define OPCODE(ID, VAL) ID = VAL,
#include "shuriken/disassembler/Dex/definitions/dvm_types.def"
        };

        static const std::unordered_map<Mnemonic, std::string> opcodeNames{
#define INST_NAME(OP, NAME) {OP, NAME},
#include "shuriken/disassembler/Dex/definitions/dvm_inst_names.def"
        };

    } // namespace disassembly
} // namespace shurikenapi