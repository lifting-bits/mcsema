# Things have gone wrong, now what?

This document describes some approaches to debugging the lifted bitcode produced by McSema on Linux. This document does not describe [how to add missing instructions](AddAnInstruction.md), or how to [resolve common errors](CommonErrors.md).

#### Terminology

This document uses the term "original binary" to mean the binary that was disassembled using `mcsema-disass`. This document uses "native code" to mean machine code in the original binary.

This document uses the term "lifted code" to mean the binary and machine code produced by compiling the bitcode produced by `mcsema-lift`.

## Set yourself up for success

There are a few helpers for using GDB to debug lifted bitcode. Some setup before debugging is in order.

First, open up `~/.gdbinit`, add the below code to that file, and save it.

```
set history filename ~/.gdb_history
set history save
set history size 4096
set pagination off
set auto-load safe-path /
set disassembly-flavor intel
set language c++
```

The `set pagination off` means that you won't always need to press Enter for GDB to print out more stuff. That gets annoying fast!

The `set auto-load safe-path /` tells GDB that it can open up a `.gdbinit` file anywhere. The McSema repository comes with a [`.gdbinit`](/.gdbinit) file, and so if you run `gdb` from within the root directory of the repository, then GDB will auto-load that file and its commands. If you do not trust this, then omit that line, and manually run `source /path/to/mcsema/.gdbinit` from within the GDB console.

The `set disassembly-flavor intel` tells GDB that it should disassemble instructions using Intel syntax, the one true syntax.

Finally, `set language c++` tells GDB that the source code that you will be debugging is C++. This is always a good option, because it's a good choice for both C and C++ debugging. GDB can usually do a pretty decent job with things like C++ std container data structures.

## Take stock of what's available

There are opportunities and drawbacks to debugging lifted code.

**Drawbacks**

 - Lifted code is more verbose than native code. An instruction from the original binary may be represented by tens of instructions in the lifted code.
 - Lifted code does not contain the useful debug information that may allow one to view the source code associated with some bits of machine code.

**Opportunities**

 - The [`RegState`](/mcsema/Arch/X86/Runtime/State.h) is stored in memory. The advantage to this is that one can set data breakpoints (hardware watchpoints) on individual registers in the state structure. This is incredibly useful if you have a [time-travelling debugger](http://undo.io/products/undodb/).
 - Lifted bitcode can be instrumented using the LLVM toolchain. Some useful-for-debugging instrumentations come built-in to `mcsema-lift`. 

### Built-in instrumentation

`mcsema-lift` comes with two useful instrumentations that can help during debugging: `-add-breakpoints` and `-add-reg-tracer`.

#### Breakpoint functions with `-add-breakpoints`

One of the aforementioned drawbacks when trying to debug lifted code is that it is more verbose. This verbosity makes things hard if you're trying to debug the translation of a specific instruction in the original binary, or if you're trying to pause execution at a specific spot.

That is why there is the `-add-breakpoints` option. The idea is that, just as you can say `b *0x402a00` to set a breakpoint on an instruction in the original binary, you can also do `b breakpoint_402a00` to set a breakpoint on the location of an "original instruction", but in the lifted binary.

| Native code | Lifted code with breakpoint functions |
| - | - |
| ![Native code](images/breakpoint_orig_code.png) | ![Lifted code](images/breakpoint.png) |


On the left we see two instructions from the native code. On the right, we see the lifted code associated with the first native instruction.

#### Register tracing with `-add-reg-tracer`
