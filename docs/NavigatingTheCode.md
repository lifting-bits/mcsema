# Navigating the code

This document describes the structure of the McSema codebase, where to find things, and how the various parts of the McSema toolchain fit together.

There are three high-level steps to using McSema:

1. [Disassembling a program binary and producing a CFG file](#disass)
2. [Lifting the CFG file into LLVM bitcode](#lift)
3. Compiling the LLVM bitcode into a runnable binary

## File Layout

First, let's familiarize ourselves with essentials of the file layout of McSema.

```shell
┌── mcsema
│   ├── Arch
│   │   ├── ...             : Architecture-neutral files
│   │   └── X86
│   │       └── Runtime     : Compiling and running lifted X86 bitcode
│   ├── BC
│   │   ├── Callback.cpp    : Produces bitcode for handling function pointers
│   │   ├── External.cpp    : Declares external functions referenced by the code
│   │   ├── Function.cpp    : Lifts functions into bitcode
│   │   ├── Instruction.cpp : Lifts instructions into bitcode
│   │   ├── Legacy.cpp      : Makes the lifted bitcode compatible with McSema v1
│   │   ├── Lift.cpp        : Lifts a binary into bitcode
│   │   ├── Optimize.cpp    : Optimizes the bitcode
│   │   ├── Segment.cpp     : Lifts data segments into bitcode
│   │   └── Util.cpp        : General utilities.
│   └── CFG
│       ├── CFG.cpp         : Decodes CFG files into rich data structures
│       └── CFG.proto       : CFG file format description
└── tools
    ├── mcsema_disass       : mcsema-disass front-end, makes CFG files
    │   ├── binja           :
    │   │   └── ...         : Binary Ninja backend for mcsema-disass
    │   ├── defs
    │   │   ├── linux.txt   : List of known external library functions on Linux
    │   │   └── windows.txt : List of known external library functions on Windows
    │   ├── ida
    │   │   └── ...         : IDA Pro backend for mcsema-disass
    │   ├── __init__.py
    │   └── __main__.py
    ├── mcsema_lift
    │   └── Lift.cpp        : mcsema-lift front-end, makes bitcode from CFG files
    └── regtrace            : Intel PIN tool for identifying divergences in lifted code
```

## <a id="disass"></a> Producing a CFG file

The first step to using McSema is to disassemble a program binary and produce a [CFG file](/mcsema/CFG/CFG.proto). The program that disassembles binaries is [`mcsema-disass`](/tools/mcsema_disass).

### `mcsema-disass`

`mcsema-disass` is organized into a [frontend](/tools/mcsema_disass/__main__.py) and backend. The front-end command accepts a `--disassembler` command-line argument that tells it what disassembly engine to use. In practice, this will always be a path to IDA Pro.

The front-end is responsible for invoking the backend and disassembly engine. The IDA Pro [backend](/tools/mcsema_disass/ida/get_cfg.py) is an IDA Python script invoked by `idal` or `idal64`, and will output a CFG file.

### CFG files, a closer look

The most important high-level structures recorded in the CFG file are:

- `Function`: functions in the binary with concrete implementations. The `Function` message contains all basic blocks and instructions of the function. A common example of this would be a program's `main` function.
- `Segment`: Data stored in the program binary. This includes things like global variables and `static` storage duration-defined variables in C/C++ code.
- `ExternalFunction`: functions called but not defined by the program. A common example of this would be libc functions like `malloc`, `strlen`, etc.
- `ExternalVariable`: data referenced but not defined by the program. An example of this would be the `getopt` C library's `optind` variable. You can things of these being like `extern`-declared global variables.

`mcsema-lift-M.m` (where `M` is the major LLVM version, and `m` is the minor LLVM version, e.g. `mcsema-lift-4.0`) has different ways of turning each of the above structures into LLVM bitcode.

## <a id="lift"></a> Lifting a CFG file

The `mcsema-lift-M.m` command is used to lift CFG files to LLVM bitcode. The four most important arguments to `mcsema-lift` are:

1. `--os`: The operating system of the code being lifted. In practice, each binary format is specific to an operating system. ELF files are for Linux, Mach-O files for macOS, and DLL files for Windows. This is one of `linux`, `macos`, or `windows`.
2. `--arch`: The architecture of the code being lifted. This is one of `x86`, `x86_avx`, `amd64`, `amd64_avx`, or `aarch64`.
3. `--cfg`: The path for the CFG file produced by `mcsema-disass`.
4. `--output`: The path to the bitcode file to save/produce.

The above arguments instruct the [lifter](/tools/mcsema_lift/Lift.cpp) on how to configure the bitcode file.

### Decoding the CFG file

McSema decodes the CFG file (passed to `--cfg`) after all architecture- and OS-specific initialization is performed. The [`ReadProtoBuf`](/mcsema/CFG/CFG.cpp) reads the contents of the CFG file produced by `mcsema-disass`, and converts the various CFG components in-memory data structures.

There are several steps involved in the decoding of the CFG file. The key challenges of decoding is resolving the various forms of cross-reference data, and handling possible symbol collisions.

### Lifting the code

The [`LiftCodeIntoModule`](/mcsema/BC/Lift.cpp) does the bulk of the lifting work. The function is mostly self-documenting:

```c++
bool LiftCodeIntoModule(const NativeModule *cfg_module) {
  DeclareExternals(cfg_module);
  DeclareLiftedFunctions(cfg_module);

  // Segments are inserted after the lifted function declarations are added
  // so that cross-references to lifted code are handled.
  AddDataSegments(cfg_module);

  // Lift the blocks of instructions into the declared functions.
  if (!DefineLiftedFunctions(cfg_module)) {
    return false;
  }

  // Add entrypoint functions for any exported functions.
  ExportFunctions(cfg_module);

  // Export any variables that should be externally visible.
  ExportVariables(cfg_module);

  // Generate code to call pre-`main` function static object constructors, and
  // post-`main` functions destructors.
  CallInitFiniCode(cfg_module);

  OptimizeModule();

  return true;
}
```

The `DefineLiftedFunctions` function does the bulk of the lifting. For each disassembled function, it creates one LLVM function, and then lifts the basic blocks of machine code instructions into that LLVM function.
