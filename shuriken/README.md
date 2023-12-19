# Shuriken Library

This folder belongs to the main part of the project. Shuriken is a library aimed 
to parse and analyze bytecode files: `.class` and `.dex`. The library will contain
different modules dedicated to: parsing the file structures, disassembly the bytecode
and finally offering different analyses with these bytecodes.

The project has the next structure:

* include/: headers from the library.
* lib/: source files from the library.
  * lib/common/: code that can be used by the rest of the project.
  * lib/parser/: different parsers for the supported files.
    * lib/parser/Dex/: Code from the DEX parser.
* external/: projects that are used inside of Shuriken but are not part of the code.


