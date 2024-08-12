# Shuriken-Analyzer

<p align="center">
  <img src="Imgs/Logo 5cm/Logo-5cm-redes-blanco.png"
alt="Shuriken Logo White"/>
</p>



Welcome to the repository of Shuriken Analyzer, a library intended for bytecode analysis!
Shuriken is an evolution from [Kunai-Static-analyzer](https://github.com/Fare9/KUNAI-static-analyzer) project, 
where the architecture of the library has been modified in order to better adapt it to other bytecodes. Shuriken
is intended to offer analysts parsing, disassembly and analysis capabilities, and it is planned to have
an improved version of the Intermediate Representation (IR) provided by Kunai.

Inside the repository you will find the next folders:

* [shuriken](./shuriken/): folder with the code from the main library. Here the core code from Shuriken is written
the code from the parsers, the disassemblers, etc.
* [shuriken-dump](./shuriken-dump/): command line tool for dumping the structure of a DEX file (for the moment).

## Installation
To install, start by cloning the respotory and then run the following commands:

```bash
 cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Release  && cmake --build build/ -j && sudo cmake --install build/
```

This helps:
- Configure the project to be built in Release mode
- Build the project with all the cores
- Install the project in usr/local/bin, thus needing sudo permissions

For uninstalling, run
```bash
sudo cmake --build build/ --target uninstall
```

to uninstall the project. Again, since we are remove files from /usr/local/, sudo permissions are needed.



## APIs In Other Programming Languages

For supporting other programming languages, we are working on offering a shim API in C. Once we have a stable
API in C, we plan to start writing the APIs for other languages, right now we plan the next APIs:

* C API
* Python API


## The Project

The project is still in an "alpha" version, but we are in continuous development. If you want to help do not hesitate
to open an issue, or if you want to write some code, check opened issues and read the [CONTRIBUTING.md](./CONTRIBUTING.md)
which contains a few points about the coding style of the project.

The logo has been designed and created by [ShanShan Bu](https://www.linkedin.com/in/shanshan-bu/), and now distributed
under Creative Common License.

<p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/">
<span property="dct:title">Shuriken Analyzer Logo</span> by 
<a rel="cc:attributionURL dct:creator" property="cc:attributionName" href="https://www.linkedin.com/in/shanshan-bu/">
ShanShan Bu</a> is licensed under <a href="http://creativecommons.org/licenses/by-sa/4.0/?ref=chooser-v1" target="_blank" 
rel="license noopener noreferrer" style="display:inline-block;">
Attribution-ShareAlike 4.0 International<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" 
src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1">
<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" 
src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1">
<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/sa.svg?ref=chooser-v1">
</a></p>
