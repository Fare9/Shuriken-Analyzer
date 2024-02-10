# Binary Ninja Plugin Suite for Shuriken-Analyzer


* view-dex - "A binary ninja view plugin for parsing the dex file format"
* arch-dex - "A binary ninja arch plugin for disassembling and lifting smali code"
* view-java - "A binary ninja view plugin for parsing the java class file format"
* arch-java - "A binary ninja view plugin for parsing the java bytecode file format"
* shuriken-suite - "a binary ninja gui plugin for assisting dex/java RE"


# Building the plugins

The plugin suite is part of the main shruiken project how its disabled by default.

To enable building the plugins add the following additional switches to the cmake command

`-DBUILD_BINJA_PLUGIN=ON -DBN_INSTALL_DIR=<path to install binaryninja>`

# Installation

## Windows

copy `view-dex.dll` to `%APPDATA%\Binary Ninja\plugins`