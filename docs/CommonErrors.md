# Common McSema Errors

This document describes common errors and fixes to problems faced when running `mcsema-lift` and `mcsema-disass`. If you are facing problems when running the compiled bitcode then check out the [Debugging Tips](DebuggingTips.md) document.

## Segfaults, segfaults everywhere

So, you've got a case of the segfaults. Lets try to diagnose the issue.

Most likely, you've got a case of CFG recovery failure. Here are some common causes:

### Lifting position independent code without `--pie-mode`

When `mcsema-lift` sees an instruction like `mov rax, 0x60008`, it needs to know whether that `0x60008` is a constant value, or whether it references code or data somewhere in the program at location `0x60008`. IDA is pretty good at figuring out the difference, but not always. Sometimes McSema just has to make an educated guess. On binaries built with position independent code (`-pie`, `-fPIC`), the default heuristic is wrong. You want to use `mcsema-disass --pie-mode` for more correct behavior.

How can you tell which to use? Check the binary type.

```shell
$ file my-pie-binary
my-pie-binary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, ...
```

If you see the words `LSB shared object`, you probably want to use `--pie-mode`. This isn't a 100% reliable heuristic; if you are having segfault issues try `--pie-mode` to see if it helps.

**Technical Details:** Using `--pie-mode` McSema assumes values it encounters are constants. Normally, McSema is biased towards immediate values that fall into the code or data section as being references.

## Errors when using `mcsema-disass`

### Unknown External `<Function Name>`

The error in the `mcsema-disass` output log looks something like this:

```shell
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
```

**Technical Background:** McSema needs to know how to call external functions, including the function calling convention and number of arguments. It knows how to call many common functions, but you hit one that it does not know about.

**Possible Fixes:** Add an entry to the [external function definitions file](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/defs) describing the function's calling convention and number of arguments. Don't forget to re-build `mcsema-disass`. Submit a pull request so we can include it in future McSema releases. Alternatively, you can specify a custom definitions file location by using the `--std-defs` argument (e.g. `mcsema-disass --std-defs /path/to/my/defs/file.txt ...`).

### Could not parse function type

You are trying to disassemble a binary and see something like the following in the output log:

```shell
Could not parse function type:__int64(void)
Traceback (most recent call last):
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 2287, in <module>
    recoverCfg(eps, outf, args.exports_are_apis)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1890, in recoverCfg
    F = entryPointHandler(M, fea, fname, exports_are_apis)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 265, in entryPointHandler
    (argc, conv, ret) = getExportType(name, ep)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 2023, in getExportType
    return parseTypeString(tp, ep)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 2001, in parseTypeString
    raise Exception("Could not parse function type:"+typestr)
Exception: Could not parse function type:__int64(void)
```

**Technical Background:** Mcsema tries to parse IDA's type signatures for functions it doesn't know about. The type signature parsing is a last ditch effort, and it failed.

**Possible Fixes:** The most likely thing that happened is you specified a bad entry point, or forgot to specify and entry point and mcsema is trying to lift every function. Eventually it hits the decorated name of an external function, can't identify it, and tries to parse type signatures.

**Debugging Hints:** Make sure you specify an entrypoint when using `mcsema-disass` (e.g. `--entrypoint main`).

## Errors when using `mcsema-lift`

### Error translating instruction

The error message reads similar to:

```shell
Error translating instruction at 4007cf; unsupported opcode 176
```

**Technical Background:** The semantics of the instruction you are trying to translate are not yet present in McSema.

**Possible Fixes:** First, you could implement the instruction semantics, and submit a pull request with the implementation. Second, you can try to use the `-ignore-unsupported` flag to `mcsema-lift` so McSema will silently ignore this unsupported instruction. Missing instructions may or may not matter, depending on what you want to do with the translated bitcode.

**Debugging Hints:** The error message tells you the location of the instruction in the binary, and its LLVM MC-layer opcode. This information will help in implementing the instruction. In the case of our example message, the instruction is `aeskeygenassist`:

```shell
$ objdump -x -d our_binary | grep 4007cf
  4007cf:       66 0f 3a df d1 00       aeskeygenassist $0x0,%xmm1,%xmm2
```

The `llvm-mc` tool can then tell you more about how the LLVM MC layer identifies the instruction:

```shell
$ echo 'aeskeygenassist $0x0,%xmm1,%xmm2' | llvm-mc-3.8 -assemble -show-inst
        .text
        aeskeygenassist $0, %xmm1, %xmm2 # <MCInst #176 AESKEYGENASSIST128rr
                                        #  <MCOperand Reg:128>
                                        #  <MCOperand Reg:127>
                                        #  <MCOperand Imm:0>>
```

In this case, we'd need to add an entry for `X86::AESKEYGENASSIST128rr` in the instruction dispatch map to implement `aeskeygenassist`.

### Basic Block does not have a terminator

You are translating a binary, and you see something that resembles the following output:

```shell
...
Adding entry point: main
main is implemented by sub_804e570
Basic Block in function 'strcoll' does not have terminator!
label %190
Could not verify module!
```

**Technical background:** LLVM requires that every basic block end in a terminating instruction (e.g. call, ret, branch, etc.). For some reason, the McSema-generated IR created a block that does not end in a terminator.

**Possible fixes:** There is likely a bug in an instruction implementation. Does your instruction create new blocks? If yes, did you update the "current block to add stuff to" (the `block` argument to the instruction implementation handler)? It is passed as a reference to a pointer, so `block = newBlock;` will update it.

**Debugging Hints:** Use the `--print-before-all` flag to `mcsema-lift` to dump generated IR to a file. Look through it backwards to identify the terminator-less block, and its corresponding x86 instruction.

### NIY Error

You get an error that says "NIY" and has a line number, for example:

```shell
error:
/home/user/mcsema/mcsema/cfgToLLVM/x86Instrs_String.cpp:773
: NIY
```

**Technical Background:** Congratulations! You hit a part of McSema that we thought about, but didn't finish implementing.

**Possible Fixes:** The best option is to implement the missing functionality and submit a pull request :). Alternatively, file an issue on GitHub and provide us a binary so that we can reproduce the problem.

**Debugging Hints:** To know more about the problem, look at the line number in the error message. The line may be a macro, so you may need to find the macro definition to see the root cause of the problem.

### StoreInst assertion failure

When using `mcsema-lift` you see an assertion failure in StoreInst like the following:

```shell
mcsema-lift: /store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp:1304: void llvm::StoreInst::AssertOK(): Assertion `getOperand(0)->getType() == cast<PointerType>(getOperand(1)->getType())->getElementType() && "Ptr must be a pointer to Val type!"' failed.
Aborted (core dumped)
```

**Technical Background:** There is an LLVM `store` instruction, and the type of what you're trying to store and where you are trying to put it are different.

**Possible Fixes:** The core issue is probably a bitness mismatch between the destination and the value. For example, you are trying to write an `i32` value into an `i64*` pointer, or vice versa. Mcsema must be fixed to use the correct bitwidth. Luckily, this is likely simple.

**Debugging Hints:** Use a debugger to launch `mcsema-lift`, and identify the instruction from the backtrace. Here is an example:

```shell
Program received signal SIGABRT, Aborted.
0x00007ffff6418428 in __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:54
54      ../sysdeps/unix/sysv/linux/raise.c: No such file or directory.
(gdb) bt
#0  0x00007ffff6418428 in __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:54
#1  0x00007ffff641a02a in __GI_abort () at abort.c:89
#2  0x00007ffff6410bd7 in __assert_fail_base (fmt=<optimized out>, assertion=assertion@entry=0x1129956 "getOperand(0)->getType() == cast<PointerType>(getOperand(1)->getType())->getElementType() && \"Ptr must be a pointer to Val type!\"",
    file=file@entry=0x112869c "/store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp", line=line@entry=1304, function=function@entry=0x11298ec "void llvm::StoreInst::AssertOK()") at assert.c:92
#3  0x00007ffff6410c82 in __GI___assert_fail (assertion=0x1129956 "getOperand(0)->getType() == cast<PointerType>(getOperand(1)->getType())->getElementType() && \"Ptr must be a pointer to Val type!\"",
    file=0x112869c "/store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp", line=1304, function=0x11298ec "void llvm::StoreInst::AssertOK()") at assert.c:101
#4  0x0000000000c1961e in llvm::StoreInst::AssertOK (this=0x9a3fe40) at /store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp:1302
#5  0x0000000000c19ad3 in llvm::StoreInst::StoreInst (this=0x9a3fe40, val=0x9a3fdc0, addr=0x9a3fc98, isVolatile=false, Align=0, Order=llvm::NotAtomic, SynchScope=llvm::CrossThread, InsertAtEnd=0x9a2b1e0)
    at /store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp:1362
#6  0x0000000000c19893 in llvm::StoreInst::StoreInst (this=0x9a3fe40, val=0x9a3fdc0, addr=0x9a3fc98, isVolatile=false, Align=0, InsertAtEnd=0x9a2b1e0) at /store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp:1330
#7  0x0000000000c19799 in llvm::StoreInst::StoreInst (this=0x9a3fe40, val=0x9a3fdc0, addr=0x9a3fc98, isVolatile=false, InsertAtEnd=0x9a2b1e0) at /store/artem/git/mcsema/third_party/llvm/lib/IR/Instructions.cpp:1321
#8  0x00000000005a7d71 in INTERNAL_M_WRITE (width=32, addrspace=0, b=0x9a2b1e0, addr=0x9a3fbd8, data=0x9a3fdc0) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.cpp:132
#9  0x00000000006762e9 in M_WRITE<32> (ip=0x5873c20, b=0x9a2b1e0, addr=0x9a3fbd8, data=0x9a3fdc0) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.h:136
#10 0x0000000000676020 in doMIMovV<32> (ip=0x5873c20, b=@0x7fffffffd730: 0x9a2b1e0, dstAddr=0x9a3fbd8, src=0x9a3fdc0) at /store/artem/git/mcsema/mcsema/cfgToLLVM/x86Instrs_MOV.cpp:473
#11 0x000000000066d2b9 in translate_MOV32mi (ctx=..., block=@0x7fffffffd730: 0x9a2b1e0) at /store/artem/git/mcsema/mcsema/cfgToLLVM/x86Instrs_MOV.cpp:643
#12 0x00000000005b7db6 in LiftInstIntoBlockImpl (ctx=..., block=@0x7fffffffd730: 0x9a2b1e0) at /store/artem/git/mcsema/mcsema/cfgToLLVM/x86Instrs.cpp:138
#13 0x00000000005ad51a in LiftInstIntoBlock (ctx=..., block=@0x7fffffffd730: 0x9a2b1e0, doAnnotation=true) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.cpp:407
#14 0x00000000005ad25e in LiftBlockIntoFunction (ctx=...) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.cpp:440
#15 0x00000000005acec9 in InsertFunctionIntoModule (mod=0x72093b0, func=0x586e550, M=0x16d2060) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.cpp:509
#16 0x00000000005ac814 in LiftFunctionsIntoModule (natMod=0x72093b0, M=0x16d2060) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.cpp:937
#17 0x00000000005aaee4 in LiftCodeIntoModule (natMod=0x72093b0, M=0x16d2060) at /store/artem/git/mcsema/mcsema/cfgToLLVM/raiseX86.cpp:952
#18 0x00000000005544a0 in main (argc=11, argv=0x7fffffffdec8) at /store/artem/git/mcsema/mcsema/Lift.cpp:124
```

This tells us the problem is in the `MOV32mi` instruction. That instruction writes a 32-bit value to memory, so the core issue is probably a 32-bit pointer and a 64-bit value mismatch, because the architecture for this specific program is `amd64`. Looking at the code at line 643 we see:

```c++
640         data_v = IMM_AS_DATA_REF(block, natM, ip);
641       }
642
643       doMIMovV<32>(ip, block, ADDR_NOREF(0), data_v);
```

The `IMM_AS_DATA_REF` function returns an architecture sized pointer, which in this case would be 64-bit. The MOV itself will be to a 32-bit value. Problem found: we are trying to put an `i64` into an `i32*` pointer! The solution is to replace `IMM_AS_DATA_REF` with `IMM_AS_DATA_REF<32>`, which will return a 32-bit value.

## Errors rebuilding binaries from Bitcode

### LLVM ERROR: expected relocatable expression

You are trying to recompile bitcode into a new binary, but clang crashes with the following error:

    LLVM ERROR: expected relocatable expression

**Technical Background:** This is most likely a sign you mismatched the architecture between CFG recovery and translation.

If you are sure you didn't, this is a combination of CFG recovery problem and clang bug. McSema is emitting bitcode that takes the lower 32-bits of a 64-bit function pointer, and puts it in a data section. Clang does not want to do this. This may be a CFG recovery bug if somehow only the lower 32-bits were detected as a function pointer. Unfortunately, some compilers emit just the lower 32-bits of a pointer into the data section. McSema has no choice but to deal with it as best it can.

**Possible Fixes:** Make sure you use the correct architecture (x86, amd64) for both the translation and CFG recovery.

If that fails, disassemble the bitcode with `llvm-dis`. Look for lines similar to the ones below. Specifically, you are looking for `ptrtoint` that converts a pointer to a 32-bit integer.

```llvm
@data_600e00 = internal global %3 <{ i32 ptrtoint (void ()* @callback_sub_400790 to i32), [4 x i8] zeroinitializer }>, align 64
@data_600e08 = internal global %4 <{ i32 ptrtoint (void ()* @callback_sub_400770 to i32), [4 x i8] zeroinitializer }>, align 64
```

If these data sections are not used, delete them and recompile the bitcode with `llvm-as`. Alternatively, remove the `zeroinitializer` padding and expand the `ptrtoint` to 64 bits. This will also require editing the structure types of the data sections:

```llvm
%3 = type <{ i64 }>
%4 = type <{ i64 }>
...
@data_600e00 = internal global %3 <{ i64 ptrtoint (void ()* @callback_sub_400790 to i64) }>, align 64
@data_600e08 = internal global %4 <{ i64 ptrtoint (void ()* @callback_sub_400770 to i64) }>, align 64
```

Neither of these fixes is guaranteed to work.
