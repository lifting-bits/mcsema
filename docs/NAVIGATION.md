# Source Navigation

This document describes where in the code features of `mc-sema` are located. Additionally, this document describes some of the internal functions and macros that are used throughout the code.

## CFG Recovery

The high-level actions of the CFG recovery code are in `bin_descend/get_cfg.py`. McSema uses IDA Pro for disassembling programs and producing CFG files.

###  `llvm::MCInst` and `NativeInst`

The `llvm::MCInst` class is defined by LLVM and stores the disassembly of a machine instruction. Unfortunately, the class is missing control flow related information and other data useful for translation. The `Inst` class, defined in `peToCFG/peToCFG.h`, augments `llvm::MCInst` with data not needed by LLVM itself. For instance, `Inst` records instruction prefixes, whether the instruction is the last in a block, whether any others point to it, whether it references external data, etc. All of the `mc-sema` code will operate on `NativeInst` instances, and not `llvm:MCInst`.

New instances of the `NativeInst` class are created in `peToCFG/inst_decoder_fe.cpp`:`LLVMByteDecoder::getInstFromBuff`. The `getInstFromBuff` method starts with an `llvm::MCInst` from the LLVM disassembler, and then augments additional information: the instruction prefix, whether the instruction terminates a block, and whether it points to another instruction. Later code will then modify more instruction parameters. 

To enable some of the Inst functionality, such as determining operand location and prefix, changes to LLVM's `MCInst` class had to be made. Most of those should be in `lib/Target/X86/Disassembler/X86Disassembler.cpp` and `lib/Target/X86/Disassembler/X86DisassemblerDecoder.c`.

### Relocations / Code and Data References

Determining what is code and what is data, and what is a code or a data reference can be surprisingly difficult. This project determines the difference based on relocations and where the relocated symbols point. Hence **relocations must be enabled** for any binary processed. Sometimes relocations will appear inside of an instruction -- it is critical to determine which operand these belong do. Certain instructions, such as `MOV mem, imm32`, may require address computation for the memory operand, the immediate operand, or both. Without associating an operand with a reloaction, these instructions would not translate correctly.

## External Functions

Call instructions to external functions have an extra annotation indicating the external call and the function name, calling convention, and arument count.

External functions cannot be modeled like translated functions, and the control flow recovery tool need to know the calling convention and argument count of these extrnal functions. The calling convention and argument count are specified by an external function map file. More details on this file are in [USAGE_AND_APIS.md](USAGE_AND_APIS.md). There is a default external function map in `tests/std_defs.txt`. This function map should cover the vast majority of the Windows API and the C runtime. 

## Serialization and Deserialization

The protobuf format is defined in `peToCFG/CFG.proto`, and described in more detail in [USAGE_AND_APIS.md](USAGE_AND_APIS.md).

## Translation

Instruction translation begins life in the cfg_to_bc executable, which takes a serialized Google protocol buffer CFG, and converts it to LLVM bitcode. The high-level actions of translation are defined in `bitcode_from_cfg/cfg_to_bc.cpp`:`main` and described in this section.

First, the CFG it re-serialized via a call to `peToCFG/peToCFG.cpp`:`ReadProtoBuf`, which will in turn de-serialze the protocol buffer file. The CFG is then transformed into an `llvm::Module`, with some initial data structures populated.

Next, the real translation can begin. The raw translation loop is in `cfgToLLVM/raiseX86.cpp`:`LiftCodeIntoModule`. The first action of `LiftCodeIntoModule` is to pre-populate all defined functions (`InitLiftedFunctions`) as stubs without any code. This is done so that these functions may be referenced in the data section and by other functions, as translation happens. Then, the data sections can be inserted. After the data sections are inserted, the code contents of each function are lifted into the pre-defined LLVM functions. This is done by the `LiftFunctionsIntoModule`. Each function is lifted using the `InsertFunctionIntoModule`.

### Data Section Translation

Data sections from the CFG are transformed into bitcode in `cfgToLLVM/raiseX86.cpp`:`InsertDataSections`.

First, `InsertDataSections` will create blank stubs for every data section. Once again, the purpose is to allow cross-data section references. 

Then the actual data insertion begins. Data sections are translated to packed LLVM structures. Representing data as a packed structure lets us reference individual data items and to insert references to other code and data sections, that will be correctly relocated in bitcode. The translation happens via two nested loops: the first one loops over every data section in the CFG, and the second one loops over every item in the data section. 

For every data section item, one of three things can happen. The item can be a a data blob. If so, then it is added as a structure member. The item can be a function reference. If so, then a reference to the function is looked up in the module, and if found, is added as a structure member. Lastly, the item can be a data reference. If so, then a reference to the data section of the target is found in the module, and an offset from module start to item start is added to the data section base. This opaque address computation is crude but necessary - a data section may reference another data section which is not yet populated.

### External Function References

After data insertion, external function references are populated. These must be populated before any instruction translation, since instructions may reference these external functions. The translation loop in `LiftCodeIntoModule` is pretty straightforward: all external definitions are simply converted to an `llvm::Function` object with appropriate return type and arguments and added to the module.

### Instruction Translation

Once the external function mappings are added, each function in the CFG is translated to LLVM bitcode. The function translation is done by `cfgToLLVM/raiseX86.cpp`:`InsertFunctionIntoModule`. 

Each translated function takes a single argument, the register state. Then this register state is referenced by local variables for use within the function. The creation of the local references into the register state is done by `ArchAllocRegisterVars`.

Next, an empty LLVM `BasicBlock` is created for every machine code basic block. The basic blocks are defined ahead-of-time so that the basic blocks can be referenced when lifting control-flow instructions.

Next, the contents every basic block in the CFG is visited by `cfgToLLVM/raiseX86.cpp`:`LiftBlockIntoFunction`. This function will begin populating the block with translated instructions.

The `LiftInstIntoBlock` function does the actual intruction translation. More literally, it adds an annotation so one can tell what instruction is being translated in the resulting IR, and calls `cfgToLLVM/x86Instrs.cpp`:`LiftInstIntoBlockImpl` to do the translation. This is done in case there is a need for multiple decoders or architectures. 

`LiftInstIntoBlockImpl` is a dispatch routine that calls the appropriate translation function based on the instruction's LLVM opcode. The translation map is stored in `cfgToLLVM/InstructionDispatch.cpp`:`translationDispatchMap`. 

The `translationDispatchMap` variable is populated by `cfgToLLVM/InstructionDispatch.cpp`:`initInstructionDispatch`. The actual population routines, described briefly below, appear in their own files. The files are named `cfgToLLVM/x86Instrs_<suffix>.cpp`, where `<suffix>` correpsonds to the types of instructions translated there. 

The current dispatch functions, where they live, and what instructions they translate:

* `FPU_populateDispatchMap`: defined in `x86Instrs_fpu.cpp`, FPU related instructions.
* `MOV_populateDispatchMap`: defined in `x86Instrs_MOV.cpp`, Various forms of MOV. There are very many.
* `CMOV_populateDispatchMap`: defined in `x86Instrs_CMOV.cpp`, Variations of CMOV, the conditional MOV.
* `Jcc_populateDispatchMap`: defined in `x86Instrs_Jcc.cpp`, Jump Conditional, JNE, JBE, JZ, etc. 
* `MULDIV_populateDispatchMap`: defined in `x86Instrs_MULDIV.cpp`, Variations of MUL and DIV
* `CMPTEST_populateDispatchMap`: defined in `x86Instrs_CMPTEST.cpp`, Variations of CMP and TEST
* `ADD_populateDispatchMap`: defined in `x86Instrs_ADD.cpp`, The very many variations of ADD
* `Misc_populateDispatchMap`: defined in `x86Instrs_Misc.cpp`, INT3, CDQ, BSWAP, Flags Modification, LEA, RDTSC, some more
* `SUB_populateDispatchMap`: defined in `x86Instrs_SUB.cpp`, The very many variations of SUB
* `Bitops_populateDispatchMap`: defined in `x86Instrs_bitops.cpp`, Bitwise operations such as AND, XOR, OR, NOT, etc.
* `ShiftRoll_populateDispatchMap`: defined in `x86Instrs_ShiftRoll.cpp`, Shifts and Rolls
* `Exchanges_populateDispatchMap`: defined in `x86Instrs_Exchanges.cpp`, XCHG, XADD, and CMPXCGH variants
* `INCDECNEG_populateDispatchMap`: defined in `x86Instrs_INCDECNEG.cpp`, Variations of INC, DEC, and NEG
* `Stack_populateDispatchMap`: defined in `x86Instrs_Stack.cpp`, PUSH, POP, ENTER, LEAVE, PUSHA
* `String_populateDispatchMap`: defined in `x86Instrs_String.cpp`, MOVS, STOS, CMPS, SCAS
* `Branches_populateDispatchMap`: defined in `x86Instrs_Branches.cpp`, JMP, CALL, LOOP, RET
* `SETcc_populateDispatchMap`: defined in `x86Instrs_SETcc.cpp`, Set a bit based on condition: SETNE, SETE, etc.

### Raw Translation

This section will briefly cover raw instruction translation. For more details on the translation functions, see the ADDING AN INSTRUCTION document.

The LLVM disassembler produces its own opcodes, with each operand combination having its own opcode. For instance, the x86 `ADD` instruction has at least 31 different LLVM opcodes, with names like `ADD32ri` (add a 32-bit immediate to a 32-bit register), `ADD8mi` (add an 8-bit immediate to an 8-bit memory location), etc. 

All of these opcodes will have very similar translations, only different by operand order and memory width. To simplify translation, the core of the instruction is usually a templated function based on width that operates on two `llvm::Value` pairs that act as operands. For the `ADD` instruction, this is `cfgToLLVM/x86Instrs_ADD.cpp`:`doAddVV`. Other helper functions exist to convert immediate values and memory addresses to `llvm::Value` objects and to write the result of the addition to the correct destination (e.g. memory or register). Examples of these helper functions are `doAddRI`, `doAddMI`, etc.

All the translation functions must have the same prototype and share lots of boilerplate code. To make writing them easier, there are several helper macros defined in `cfgToLLVM/InstructionDispatch.h`:

* `GENERIC_TRANSLATION(NAME, THECALL)`: Create a function named `translate_<NAME>` that executes the statement `THECALL`.
* ` GENERIC_TRANSLATION_MEM(NAME, THECALL, GLOBALCALL)`: Like `GENERIC_TRANSLATION`, but checks if the instruction references code or data. If so, execute `GLOBALCALL` instead of `THECALL`.
* `GENERIC_TRANSLATION_32MI(NAME, THECALL, GLOBALCALL, GLOBALIMMCALL)`: Used only for instructions that have two operands: 32-bit immediate and a memory value. Like GENERIC_TRANSLATION_MEM, but checks which operand references code or data. If its the immediate, execute `GLOBALIMMCALL`.
* `OP(x)`: Shorthand for `inst.getOperand(x)`
* `ADDR(x)`: Shorthand for `getAddrFromExpr` with common arguments.
* `ADDR_NOREF(x)`: Shortang for `getAddrFromExpr` where it is **certain** the function will never reference a data variable, but needs to compute a complex address expression.

Many x86 instructions require complex address computation due to complex addressing modes. The helper following helper functions are defined in `cfgToLLVM/x86Helpers.cpp` and are used to do address computation:

* `getAddrFromExpr`: Computes a Value from a complex address expression such as `[0x123456+EAX*4]`. If the expression references global data, use that in the computation instead of assuming values are opaque immediates.
* `GLOBAL`: Shorthand for `getAddrFromExpr`.
* `GLOBAL_DATA_OFFSET`: Used when it is **certain** that the instruction must reference code/data, and not an opaque immediate. 

Using these macros, it is then possible to define a translation function. For instance, `ADD32ri` is defined as:

`GENERIC_TRANSLATION(ADD32ri, doAddRI<32>(ip, block, OP(0), OP(1), OP(2)))`

That code will define a function named `translate_ADD32ri`, and call `doAddRI<32>(ip, block, OP(0), OP(1), OP(2))` to do the translation. The result will be stored in operand 0, and the two addends are operand 1 and operand 2. 

### Writing a Translation Function

The best way to write a translation function it to use the existing functions as an example. Essentially, all the function must do is add LLVM bitcode to an existing function or basic block, and update the returned basic block pointer. Below are some helper functions that are useful in writing translation functions. These are defined in `cfgToLLVM/raiseX86.h`. Do **NOT** use the regular memory/register access functions to access floating point registers.

* `template <int width> llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t val)`: Emit a constant integer value having the value `val` and the bitwidth `width`.
* `template <int width> llvm::Value *R_READ(llvm::BasicBlock *b, unsigned reg)`: Read the value of register `reg` and put it in an integer of bitwidth `width`. It is up to you to ensure you are reading the correct width of the register. The `reg` value is specified via the `X86` enum (e.g. `X86::EAX`) or as an `MCInst` operand (e.g. `OP(1).getReg()`).
* `template <int width> void R_WRITE(llvm::BasicBlock *b, unsigned reg, llvm::Value *write)`: Same as R_READ, but for writing a value into a register.
* `template <int width> llvm::Value *M_READ(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr)`: Read `width` bits from memory address `addr`. This macro includes a reference to `ip` to determine which address space to read from. The address space is used in case of `FS` or `GS` segment prefixed instructions. 
* `template <int width> void M_WRITE(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr, llvm::Value *data)`: Just like `M_READ` but instead writes to memory.
* `llvm::Value *F_READ(llvm::BasicBlock *b, std::string flag);`: Read flag named `flag`. The names are the standardized flag names, such as `ZF`, `PF`, `OF`, etc. The FPU flags names are prefixed with `FPU_`, so the names would be `FPU_TOP`, `FPU_C1`, etc.
* `void F_WRITE(BasicBlock *b, string flag, Value *v)`: Set the flag `flag` with value `v`.
* `void F_ZAP(BasicBlock *b, string flag)`: Set flag `flag` to an undefined value.
* `void F_SET(BasicBlock *b, string flag)`: Set `flag` to 1.
* `void F_CLEAR(BasicBlock *b, string flag)`: Set `flag` to 0.

To access floating point registers, use the below functions defined in `cfgToLLVM/x86Instrs_fpu.cpp`. Do not use these functions to access regular integer registers.

* `Value *FPUR_READ(BasicBlock *&b, unsigned fpreg)`: Read ST(`fpreg`). 
* `void FPUR_WRITE(BasicBlock *&b, unsigned fpreg, Value *val)`: Write `val` into ST(`fpreg`)
* `void FPU_POP(BasicBlock *&b)`: Pop the FPU stack. Set ST(0) as empty, Increment FPU_TOP to get new ST(0).
* `void FPU_PUSHV(BasicBlock *&b, Value *fpuval)`: Push `fpuval` onto the FPU stack: decrement FPU_TOP, set ST(0) = `fpuval`.
* `Value *FPUM_READ(InstPtr ip, int memwidth, llvm::BasicBlock *&b, Value *addr)`: Read `memwidth` bits from address `addr`. 
* There is currently no `FPUM_WRITE`. FPU memory writes are done via `M_WRITE_T` which is a verison of `M_WRITE` that accepts a type to write instead of assuming integer types. See `cfgToLLVM/raiseX86.cpp`.

### Register Context Definitions

The register context is used both internally by the translator and externally by applications that must interface with translated code. Currently, these are separate definitions of an identical structure. These definitions **must** stay in sync when adding or removing registers.

The internal translator register context is built in `cfgToLLVM/toLLVM.cpp`:`doGlobalInit`. The structure is defined by code that emits an LLVM bitcode definition for `struct.regs`. The `struct.regs` will appear in all generated bitcode files.

The external register context, used by applications that link to translated code, is defined in `common/RegisterState.h`. The structure is called `RegState`, and the definition **should** be portable to Win32 and Linux. The header file also contains definitions to simplify working with native sized floating point types on both platforms.

Floating point helper functions:

* `FPU_GET_REG(RegState *state, unsigned reg_index)`: Use this to read FPU register `st(reg_index)`. This function the value of the `FPU_TOP` flag to calculate to which actual register slot the `reg_index` corresponds.
* `FPU_SET_REG(RegState *state, unsigned reg_index, nativefpu val)`: Use this to write an FPU register value. Same caveat as `FPU_GET_REG`. 
* `NATIVEFPU_TO_LD`: Convert a `struct nativefpu` to a `long double`. This is more difficult than it seems, since Win32 long doubles are not native-sized 80-bit floating point values. Conversion requires use of inline assembly.
* `LD_TO_NATIVEFPU`: Convert a `long double` to a `struct nativefpu`. Same caveats as `NATIVEFPU_TO_LD`.


## OS Specific Functionality

Some operating system specific functionality is necessary to get call by memory / call by register and callback to work correctly. These functions are found in the `win32_` prefixed files in `mc-sema\cfgToLLVM`. 

* `win32cb.{h,cpp}`: Functionality necessary for callbacks to work on Win32. Calls to native allocation functions, stack voodoo, etc. These are referenced by the various callback functions in `mc-sema\cfgToLLVM\raiseX86.cpp`, such as `makeCallbackForLocalFunction`, `getCallbackPrologueInternal`, etc. 
* `win32_Intrinsics.h`: A place to define Win32/MSVC specific intrinsic functions, such as `_aullshr`. 

## Testing

There is currently some testing infrastructure. There are two main catgories of tests, the functionality demos and the instruction semantics tests.

### Functionality Demos

The functionality demos are meant to only run on Win32 and live in `mc-sema/tests`. These serve both as demos and as tests of translating actual binaries. The demos are a series of batch files named `demo1.bat` - `demo16.bat`, `demo_sailboat.bat`, `demo_fpu1.bat`, and `demo_dll_1.bat` through `demo_dll_6.bat`. More details on these is in the [DEMOS.md](DEMOS.md) document.

### Instruction Semantics Tests

Instruction semantics tests have been temporarily removed, pending a reimplementation that simplifies the testing process.
