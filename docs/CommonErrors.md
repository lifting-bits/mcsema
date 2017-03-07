# Common McSema Errors

# Errors when using `mcsema-disass`

## Unknown External `<Function Name>`

The error in the mcsema-disass output log looks something like this:

    Unknown external: cs_open
    Traceback (most recent call last):
      File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 2287, in <module>
        recoverCfg(eps, outf, args.exports_are_apis)
      File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1893, in recoverCfg
        recoverFunction(M, F, fea, new_eas)
      File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1693, in recoverFunction
        recoverFunctionFromSet(M, F, blockset, new_eas)
      File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1681, in recoverFunctionFromSet
        I, endBlock = instructionHandler(M, B, head, new_eas)
      File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 817, in instructionHandler
        if doesNotReturn(fn):
      File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 220, in doesNotReturn
        raise Exception("Unknown external: " + fname)
    Exception: Unknown external: cs_open

**Technical Background:** Mcsema needs to know how to call external functions, including the function calling convention and number of arguments. It knows how to call many common functions, but you hit one that it does not know about.

**Possible Fixes:** Add an entry to the [external function definitions file](https://github.com/trailofbits/mcsema/tree/master/tools/mcsema_disass/defs) describing the function's calling convention and number of arguments. Don't forget to re-build `mcsema-disass`. Submit a pull request so we can include it in future mcsema releases. Alternatively, you can specify a custom definitions file location by using the `--std-defs` argument (e.g. `mcsema-disass --std-defs /path/to/my/defs/file.txt ...`). 

# Errors when using `mcsema-lift`

## Error translating and instruction

The error message reads similar to:

    Error translating instruction at 4007cf; unsupported opcode 176

**Technical Background:**: The semantics of the instruction you are trying to translate are not present in mcsema.

**Possible Fixes:** First, you could implement the instruction semantics and submit a pull request with the implementation. Second, you can try to use the `-ignore-unsupported` flag to `mcsema-lift` so mcsema will silenty ignore this unsupported instruction. Missing instructions may or may not matter, depending on what you want to do with the translated bitcode.

**Debugging Hints:** The error message tells you the location of the instruction in the binary, and its LLVM MC-layer opcode. This information will help in implmenting the instruction. In the case of our example message, the instruction is `aeskeygenassist`:
    $ objdump -x -d our_binary | grep 4007cf
      4007cf:       66 0f 3a df d1 00       aeskeygenassist $0x0,%xmm1,%xmm2

The `llvm-mc` tool can then tell you more about how the LLVM MC layer identifies the instruction:

    $ echo 'aeskeygenassist $0x0,%xmm1,%xmm2' | llvm-mc-3.8 -assemble -show-inst
            .text
            aeskeygenassist $0, %xmm1, %xmm2 # <MCInst #176 AESKEYGENASSIST128rr
                                            #  <MCOperand Reg:128>
                                            #  <MCOperand Reg:127>
                                            #  <MCOperand Imm:0>>

In this case, we'd need to add an entry for `X86::AESKEYGENASSIST128rr` in the instruction dispatch map to implement `aeskeygenassist`.

## Basic Block does not have a terminator

You are translating a binary, and you see something that resembles the following output:

    ...
    Adding entry point: main
    main is implemented by sub_804e570
    Basic Block in function 'strcoll' does not have terminator!
    label %190
    Could not verify module!

**Technical background:** LLVM requires that every basic block end in a terminating instruction (e.g. call, ret, branch, etc.). For some reason, the mcasema generated IR created a block that does not end in a terminator.

**Possible fixes:** There is likely a bug in an instruction implementation. Does your instruction create new blocks? If yes, did you update the "current block to add stuff to" (the `block` argument to the instruction implementation handler)? It is passed as a reference to a pointer, so `block = newBlock;` will update it.

**Debugging Hints:**: Use the `--print-before-all` flag to `mcsema-lift` to dump generated IR to a file. Look through it backwards to identify the terminator-less block, and its corresponding x86 instruction.


## NIY Error

You get an error that says "NIY" and has a line number, for example:

    error:
    /home/user/mcsema/mcsema/cfgToLLVM/x86Instrs_String.cpp:773
    : NIY

**Technical Background:** Congratulations! You hit a part of mcsema that we thought about, but didn't finish implementing. 

**Possible Fixes:** The best option is to implement the missing functionality and submit a pull request :). Alternatively, file an issue on Github and provide us a binary so we can reproduce the problem.

**Debugging Hints:** To know more about the problem, look at the line number in the error message. The line may be a macro, so you may need to find the macro definition to see the root cause of the problem.

# Errors rebuilding binaries from Bitcode

## LLVM ERROR: expected relocatable expression

You are trying to recompile bitcode into a new binary, but clang crashes with the following error:

    LLVM ERROR: expected relocatable expression

**Technical Background:** This is most likely a sign you mismatched the architecture between CFG recovery and translation. 

If you are sure you didn't, this is a combination of CFG recovery problem and clang bug. Mcsema is emitting bitcode that takes the lower 32-bits of a 64-bit function pointer, and puts it in a data section. Clang does not want to do this. This may be a CFG recovery bug if somehow only the lower 32-bits were deteted as a function pointer. Unfortunately, some compilers emit just the lower 32-bits of a pointer into the data section. Mcsema has no choice but to deal witht it as best it can.

**Possible Fixes:** Make sure you use the correct architecture (x86, amd64) for both the translation and CFG recovery.

If that fails, disassemble the bitcode with `llvm-dis`. Look for lines similar to the ones below. Specifically, you are looking for `ptrtoint` that converts a pointer to a 32-bit integer.

    @data_600e00 = internal global %3 <{ i32 ptrtoint (void ()* @callback_sub_400790 to i32), [4 x i8] zeroinitializer }>, align 64
    @data_600e08 = internal global %4 <{ i32 ptrtoint (void ()* @callback_sub_400770 to i32), [4 x i8] zeroinitializer }>, align 64

If these data sections are not used, delete them and recompile the bitcode with `llvm-as`. Alternatively, remove the `zeroinitializer` padding and expand the `ptrtoint` to 64 bits. This will also require editing the structure types of the data sections:

    %3 = type <{ i64 }>
    %4 = type <{ i64 }>
    ...
    @data_600e00 = internal global %3 <{ i64 ptrtoint (void ()* @callback_sub_400790 to i64) }>, align 64
    @data_600e08 = internal global %4 <{ i64 ptrtoint (void ()* @callback_sub_400770 to i64) }>, align 64

Neither of these fixes is guaranteed to work.

