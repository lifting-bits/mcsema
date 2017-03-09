# Adding a New Instruction

There are two basic steps to adding an instruction:

* Implement the semantics
* Glue semantics to the rest of mcsema

A lot of helper code already exists to help with both parts of instruction addition.

## Implementing Semantics

Typically you will want to edit an existing file in `mcsema/Arch/X86/Semantics`, copy the semantics of an existing instruction with similar semantics and modify it to fully reflect the new instruction.

## Helper Functions

Here are some common helper functions and macros you may need when implementing instructions:

### `GENERIC_TRANSLATION`

Example:

    GENERIC_TRANSLATION(UNPCKLPSrr, (doUNPCKLPSrr(block, OP(1), OP(2))))

This macro emits a function named `translate_<NAME>` (e.g. `translate_UNPCKLPSrr`) that has the right signature for the dispatch map, and calls the second argument as the semantics implementation.


### `GENERIC_TRANSLATION_REF`, `ADDR_NOREF`, and `MEM_REFERENCE`

All three of these typically go together, so we'll talk about them all at once.

Example:

    GENERIC_TRANSLATION_REF(UNPCKLPSrm,
                            (doUNPCKLPSrm(ip, block, OP(1), ADDR_NOREF(2))),
                            (doUNPCKLPSrm(ip, block, OP(1), MEM_REFERENCE(2)))

This is a version of `GENERIC_TRANSLATION` but for instructions that can reference memory (e.g. they take a 32-bit immediate operand or a memory operand).

The macro will test if the specific instruction references memory, if no, then the first function is called, if yes, then the second.

The `ADDR_NOREF` macro will treat an operand as being an immediate value that does not reference anything, even if the value would have pointed to a code or data section. The lone argument to it is the operand number of the operand as understood by LLVM's MC layer.

The `MEM_REFERENCE` macro will treat and operand as referencing something in the program. It will attempt to match the referenced address with a function, variable, or data section and ensure the reference works.

## `GENERIC_TRANSLATION_MI` and `IMM_AS_DATA_REF`

This is a version of `GENERIC_TRANSLATION` that is used for operations that can reference memory via an immediate operand and a memory operand (e.g. `ADD [memory], 32-bit immediate`).

Example:

    GENERIC_TRANSLATION_MI(
        ADC32mi, doAdcMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
        doAdcMV<32>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
        doAdcMV<32>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

This macro takes an instruction name and 4 arguments. The arguments are as follows:

1) Instruction semantics if there are no references at all
2) Instruction semantics if the memory operand has a reference
3) Instruction semantics if the memory operand is not a reference, but the immediate operand references something in the program
4) Instruction semantics if both the memory operand and the immediate operand reference something in the program

The `IMM_AS_DATA_REF` macro will treat the instruction's immediate operand as a reference to the program. 

## Glue Code

If you created any new files, make sure to add them to the build by editing `CMakeLists.txt`.

Otherwise look at the bottom of the file you edited. There is a function, called `<NAME>_populateDispatchMap` which fills out a map of LLVM MC layer instruction to semantics function. That map is how `mcsema-lift` knows about which instructions exist. Make sure you add your implementation to the map, or your code will never be called.

# Add An Instruction Walkthrough

This section describes how to add new instruction semantics

For this example, we will be adding the `FSIN` instruction.

## Which file to change?

First, examine the files in `mcsema/Arch/X86/Semantics`. It is very likely that the instruction you are translating falls into a category of already translated instructions. If so, select which file to modify. For `FSIN`, we will be modifying `fpu.cpp`. 

If no existing categories fit your translation (this is very unlikely):
* Use one of the existing files as a template
* Modify `CMakeLists.txt` to build your file
* Modify `mcsema/Arch/X86/Dispatch.cpp` to include your translations in the dispatch map.

### Boilerplate Code

The process of adding a new instruction starts with some boilerplate code necessary for the translation framework to see a new translation has been defined.

Add the following function in `fpu.cpp`:

    static InstTransResult doFsin(NativeInstPtr ip, llvm::BasicBlock *&b,
                              MCSemaRegs reg) {
	    return ContinueBlock;
	}

This function will do the actual translation to bitcode. Currently it is empty.

Add a call to the `FPU_TRANSLATION` macro. This macro will save you writing lots of boilerplate code.

    FPU_TRANSLATION(SIN_F, true, false, true, false,
                    doFsin(ip, block, llvm::X86::ST0))

This call indicates the following about the translation: 

* We are translating `SIN_F`
* It will set the last FPU IP register
* It will **not** set the last FPU data register (as it reads from a register). 
* It will set the last FPU opcode register
* It will **not** access memory. 
* The code to do the actual translation will be `doFsin(ip, block, llvm::X86::ST0)`.


Add the following statement in `FPU_populateDispatchMap`:

	m[llvm::X86::SIN_F] = translate_SIN_F;

The function `translate_SIN_F` will be automatically generated by the `FPU_TRANSLATION` macro.

At this point, build the project to ensure there are no build errors.

## What The Additions Do

Each file has a function named `<functionality>_populateDispatchMap` defined at the very end of the file. This function populates the dispatch map: a mapping of x86 instruction (as defined by LLVM) to a translation function that emits LLVM bitcode. The function prototype for all dispatch functions is:

    static InstTransResult translate_<INSTRUCTION NAME> (TranslationContext &ctx, llvm::BasicBlock *&block)

The x86 instructions as defined by LLVM are not the same as raw x86 opcodes. There is an instruction enum generated by LLVM at build-time, and can be found by looking in `build/llvm/lib/Target/X86/X86GenInstrInfo.inc`.

Most translations involve similar boilerplate that needs to be present prior to actual translation. Examples of this boilerplate include checking whether or not an instruction will write to memory, determining which floating point flags are modified, whether the last FPU data or last FPU opcode fields are set, and so on. This boilerplate code is encapsulated in macros, in the case of FPU related code the macro is called `FPU_TRANSLATION`.

The `FPU_TRANSLATION` macro is defined as follows:

	FPU_TRANSLATION(NAME, SETPTR, SETDATA, SETFOPCODE, ACCESSMEM, THECALL)

* `NAME`: The x86 instruction being translated, as seen by LLVM. In this case, the instruction is `SIN_F`.
* `SETPTR`: A boolean indicating whether the instruction should set the Last FPU IP register.
* `SETDATA`: A boolean indicating whether the instruction should set the Last FPU data register.
* `SETFOPCODE`: A boolean indicating whether the instruction should set the last FPU opcode register.
* `ACCESSMEM`: A boolean indicating whether this instruction accesses memory. 
* `THECALL`: Code to call to do the raw translation.

### The Translation

Modify the `doFsin` function to the following:

    static InstTransResult doFsin(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  MCSemaRegs reg) {
      auto M = b->getParent()->getParent();
      auto regval = FPUR_READ(b, reg);
    
      // get a declaration for llvm.fsin
      auto t = llvm::Type::getX86_FP80Ty(b->getContext());
      auto fsin_func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::sin, t);
    
      NASSERT(fsin_func != NULL);
    
      // call llvm.fsin(reg)
      std::vector<llvm::Value *> args;
      args.push_back(regval);
    
      auto fsin_val = llvm::CallInst::Create(fsin_func, args, "", b);
    
      // store return in reg
      FPUR_WRITE(b, reg, fsin_val);
    
      return ContinueBlock;
    }

This code will use LLVM's internal sine intrinsic to calculate the sine of a given FPU register. Since `FSIN` only operates on `st0`, this function is always called with `X86::ST0` as the reg argument. It is parametrized in case of future need to take the sine of other registers.

Rebuild the project to ensure everything works, and then move on to the Adding a Test document to ensure your instruction functions as expected.
