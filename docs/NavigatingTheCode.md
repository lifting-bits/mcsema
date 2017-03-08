# Navigating the code

This document describes the structure of the McSema codebase, where to find things, and how the various parts of the McSema toolchain fit together.

There are three high-level steps to using McSema:

 1. [Disassembling a program binary and producing a CFG file](#disass)
 2. [Lifting the CFG file into LLVM bitcode](#lift)
 3. Compiling the LLVM bitcode into a runnable binary

## File Layout

First, let's familiarize ourselve with essentials of the file layout of McSema.

```
┌── mcsema
│   ├── Arch
│   │   ├── ...               Architecture-neutral files
│   │   └── X86
│   │       ├── ...           X86-specific files
│   │       ├── Runtime
│   │       │   ├── ...
│   │       │   └── State.h   X86 `RegState` structure
│   │       └── Semantics
│   │           ├── ADD.cpp   Semantics for ADD instruction
│   │           └── ...       Other semantics code
│   │    
│   ├── BC 
│   │    ├── Lift.cpp         Bitcode lifting code
│   │    └── Util.cpp         Bitcode generation utilities 
│   │  
│   ├── CFG
│   │   ├── CFG.cpp           CFG file deserialization code
│   │   └── CFG.proto         CFG file format description
│   │  
│   ├── cfgToLLVM             Legacy translation routines
│   │   └── ...
│   │  
│   └── Lift.cpp              Entrypoint of `mcsema-lift`
│
├── tools
│   └── mcsema_disass
│       ├── ida
│       │   └── get_cfg.py    IDA script to produce CFG files           
│       └── __main__.py       Entrypoint of `mcsema-disass`               
│
└── third_party
    └── llvm                  LLVM source code
```

## <a id="disass"></a> Producing a CFG file

The first step to using McSema is to disassemble a program binary and produce a [CFG file](/mcsema/CFG/CFG.proto). The program that disassembles binaries is [`mcsema-disass`](/tools/mcsema_disass).

### `mcsema-disass`

`mcsema-disass` is organized into a [frontend](/tools/mcsema_disass/__main__.py) and backend. The front-end command accepts a `--disassembler` command-line argument that tells it what disassembly engine to use. In practice, this will always be a path to IDA Pro.

The front-end is responsible for invoking the backend and disassembly engine. The IDA Pro [backend](/tools/mcsema_disass/ida/get_cfg.py) is an IDA Python script invoked by `idal` or `idal64`, and will output a CFG file.

### CFG files, a closer look

The most important high-level structures recorded in the CFG file are:

 - `Function`: functions in the binary with concrete implementations. The `Function` message contains all basic blocks and instructions of the function. A common example of this would be a program's `main` function.
 - `ExternalFunction`: functions called but not defined by the program. A common example of this would be libc functions like `malloc`, `strlen`, etc.
 - `Data`: Data stored in the program binary. This includes things like global variables and `static` storage duration-defined variables in C/C++ code.
 - `ExternalData`: data referenced but not defined by the program. An example of this would be the `getopt` C library's `optind` variable. You can things of these being like `extern`-declared global variables.

`mcsema-lift` has different ways of turning each of the above structures into LLVM bitcode.

## <a id="lift"></a> Lifting a CFG file

The `mcsema-lift` command is used to lift CFG files to LLVM bitcode. Two important arguments to `mcsema-lift` are:

 1. `--os`: The operating system of the code being lifted. In practice, each binary format is specific to an operating system. ELF files are for Linux, Mach-O files for macOS, and DLL files for Windows.
 2. `--arch`: The architecture of the code being lifted. This is one of `x86` or `amd64`.

Both of the above arguments instruct the [lifter](/mcsema/Lift.cpp) on how to configure the bitcode file.

### Setting up

McSema self-initializes before any bitcode is produced. The first initialization step is [`InitArch`](/mcsema/Arch/Arch.cpp). This function uses the values passed to the `--os` and `--arch` command-line flags to set up a target triple and data layout for the bitcode file. The triple and data layouts tell LLVM about things like the size of pointers and calling conventions.

`InitArch` also initializes things like the instruction disassembler and [dispatcher]((/mcsema/Arch/X86/Dispatcher.cpp). McSema uses LLVM's built-in instruction disassembler. The disassembler converts bytes of machine code into `MCInst` objects. `MCInst` instructions are labelled with an "op code." McSema has a function for lifting each op code. An instruction dispatcher is used to map an instruction's op code to an function that produces bitcode.

Machine code architecture-specific functionality is isolated into the [Arch](/mcsema/Arch) directory and its sub-directories. Architecture-specific functions are prefixed using `Arch`. For example, `ArchRegisterName` is a function that returns the name of a register. This function dispatches to [`X86RegisterName`](/mcsema/Arch/X86/Register.cpp) when the value passed to the `--arch` command-line option is `x86` or `amd64`.

### Decoding the CFG file

McSema decodes the CFG file (passed to `--cfg`) after all architecture- and OS-specific initialization is performed. The [`ReadProtoBuf`](/mcsema/CFG/CFG.cpp) reads the contents of the CFG file produced by `mcsema-disass`, and converts the various CFG components in-memory data structures.

There are four steps involved:

 1. `DeserializeExternFunc`: `ExternalFunction` messages from the CFG file are decoded into [`ExternalCodeRef`](/mcsema/CFG/Externals.h) data structures.

    External functions cannot be modeled like translated functions, and the control flow recovery tool needs to know the calling convention and argument count of these external functions. The calling convention and argument count are specified by an external function map file. There is a default external function map for both [Linux](/tools/mcsema_disass/defs/linux.txt) and [Windows](/tools/mcsema_disass/defs/linux.txt). in `tests/std_defs.txt`.

 2. `DeserializeNativeFunc`: `Function` messages from the CFG file are decoded into `NativeFunc` data structures. Each one of these functions will be lifted into bitcode.

    The `Function` message contains one or more `Block` messages. These represent [basic blocks](https://en.wikipedia.org/wiki/Basic_block) of machine code. `Block` messages are decoded by `DeserializeBlock` into `NativeBlock` objects. Each one of these objects will produce one or more `llvm::BasicBlock` objects.

    Each `Instruction` message contained in the `Block` is decoded by `DeserializeInst` into a `NativeInst` object. The `NativeInst` object is produced by decoding the raw bytes of the instruction using the `DecodeInst`. `DecodeInst` uses the architecture-neutral [`ArchDecodeInstruction`](/mcsema/Arch/Arch.cpp) function to decode the instruction bytes into an `llvm::MCInst` object.

    The `NativeInst` class, augments `llvm::MCInst` with data not needed by LLVM itself. For instance, `NativeInst` records instruction prefixes, whether the instruction is the last in a block, whether any others point to it, whether it references external data, etc. All of the `mc-sema` code will operate on `NativeInst` instances, and not `llvm::MCInst`.

 3. `DeserializeData`: `Data` messages from the CFG file are decoded into `DataSectionEntry` objects. Each one of these objects will produce the equivalent of global variables.

    McSema does not always know the content or structure of the data sections within a binary. As such, it needs to preserve the content of those sections (almost) verbatim, treating them as mostly opaque blobs.

    Data sections are translated to packed LLVM structures. Representing data as a packed structure lets us reference individual data items and to insert references to other code and data sections, that will be correctly relocated in bitcode.

    There are three ways of handling `DataSectionEntry` items. The item can be a data blob. If so, then it is added as a structure member. The item can be a function reference. If so, then a reference to the function is looked up in the module, and if found, is added as a structure member. Lastly, the item can be a data reference. If so, then a reference to the data section of the target is found in the module, and an offset from module start to item start is added to the data section base. This opaque address computation is crude but necessary - a data section may reference another data section which is not yet populated.

 4. `DeserializeExternData`: `ExternalData` messages from the CFG file are decoded into `ExternalDataRef` objects. Each one of these objects is treated by the bitcode as externally-defined global variables.

### Lifting the code

The [`LiftCodeIntoModule`](/mcsema/BC/Lift.cpp) does the bulk of the lifting work. The function is mostly self-documenting:

```c++
bool LiftCodeIntoModule(NativeModulePtr natMod, llvm::Module *M) {
  InitLiftedFunctions(natMod, M);
  InitExternalData(natMod, M);
  InitExternalCode(natMod, M);
  InsertDataSections(natMod, M);
  return LiftFunctionsIntoModule(natMod, M);
}
```

`InitLiftedFunctions` creates one `llvm::Function` for every `NativeFunction` data structure.

`InitExternalData` creates global variables for every `ExternalDataRef` object.

`InitExternalCode` creates external `llvm::Function` declarations for every `ExternalCodeRef`. This involves declaring the functions with the correct prototypes that include the OS-specific calling convention, and argument and return types.

`InsertDataSections` creates the global packed structs for each `DataSectionEntry` item. The translation happens via two nested loops. The first loop iterates over every data section in the CFG. The second loop, found in [`dataSectionToTypesContents`](/mcsema/BC/Util.cpp) iterates over every item in the data section and fills their content into the bitcode file.

`LiftFunctionsIntoModule` lifts the actual instructions into the `llvm::Function`s created by `InitLiftedFunctions`. The first step to lifting each function is `InsertFunctionIntoModule`. This function starts by creating one `llvm::BasicBlock` for each of the function's `NativeBlock`s. A special entry basic block is added to the `llvm::Function`. This block creates one variable for every machine code register. The creation of the local references into the register state is done by `ArchAllocRegisterVars`.

The `LiftBlockIntoFunction` function then populates the empty `llvm::BasicBlock`s with bitcode emulating the machine code. It executes `LiftInstIntoBlock` for every `NativeInst` in the `NativeBlock` object. This function discovers the architecture-specific instruction lifter using the `ArchGetInstructionLifter` function. This function looks up the opcode of the `llvm::MCInst` in the instruction dispatcher.

The `ArchLiftInstruction` invokes the instruction-specific lifter function. This function may do some architecture-specific pre-processing before lifting the instruction.

### Raw Translation

This section will briefly cover raw instruction translation. For more details on the translation functions, see the ADDING AN INSTRUCTION document.

The LLVM disassembler produces its own opcodes, with each operand combination having its own opcode. For instance, the x86 `ADD` instruction has at least 31 different LLVM opcodes, with names like `ADD32ri` (add a 32-bit immediate to a 32-bit register), `ADD8mi` (add an 8-bit immediate to an 8-bit memory location), etc. 

All of these opcodes will have very similar translations, only different by operand order and memory width. To simplify translation, the core of the instruction is usually a templated function based on width that operates on two `llvm::Value` pairs that act as operands. For the `ADD` instruction, this is [`doAddVV`](/mcsema/Arch/X86/Semantics/ADD.cpp). Other helper functions exist to convert immediate values and memory addresses to `llvm::Value` objects and to write the result of the addition to the correct destination (e.g. memory or register). Examples of these helper functions are `doAddRI`, `doAddMI`, etc.

All the translation functions must have the same prototype and share lots of boilerplate code. To make writing them easier, there are several helper macros defined in [`mcsema/BC/Util.h`](/mcsema/BC/Util.h):

* `GENERIC_TRANSLATION(NAME, THECALL)`: Create a function named `translate_<NAME>` that executes the statement `THECALL`.
* ` GENERIC_TRANSLATION_MEM(NAME, THECALL, GLOBALCALL)`: Like `GENERIC_TRANSLATION`, but checks if the instruction references code or data. If so, execute `GLOBALCALL` instead of `THECALL`.
* `GENERIC_TRANSLATION_32MI(NAME, THECALL, GLOBALCALL, GLOBALIMMCALL)`: Used only for instructions that have two operands: 32-bit immediate and a memory value. Like GENERIC_TRANSLATION_MEM, but checks which operand references code or data. If its the immediate, execute `GLOBALIMMCALL`.
* `OP(x)`: Shorthand for `inst.getOperand(x)`
* `ADDR(x)`: Shorthand for `getAddrFromExpr` with common arguments.
* `ADDR_NOREF(x)`: Shorthand for `getAddrFromExpr` where it is **certain** the function will never reference a data variable, but needs to compute a complex address expression.

Many x86 instructions require complex address computation due to complex addressing modes. The helper following helper functions are defined in `cfgToLLVM/x86Helpers.cpp` and are used to do address computation:

* `getAddrFromExpr`: Computes a Value from a complex address expression such as `[0x123456+EAX*4]`. If the expression references global data, use that in the computation instead of assuming values are opaque immediates.
* `GLOBAL`: Shorthand for `getAddrFromExpr`.
* `GLOBAL_DATA_OFFSET`: Used when it is **certain** that the instruction must reference code/data, and not an opaque immediate. 

Using these macros, it is then possible to define a translation function. For instance, `ADD32ri` is defined as:

```c++
GENERIC_TRANSLATION(ADD32ri, doAddRI<32>(ip, block, OP(0), OP(1), OP(2)))
```

That code will define a function named `translate_ADD32ri`, and call `doAddRI<32>(ip, block, OP(0), OP(1), OP(2))` to do the translation. The result will be stored in operand 0, and the two addends are operand 1 and operand 2. 
