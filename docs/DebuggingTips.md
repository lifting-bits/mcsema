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

Finally, `set language c++` tells GDB that the source code that you will be debugging is C++. This is always a good option, because it's a good choice for both C and C++ debugging. GDB can usually do a pretty decent job with things like C++ standard library container data structures.

## Take stock of what's available

There are opportunities and drawbacks to debugging lifted code.

**Drawbacks**

 - Lifted code is more verbose than native code. An instruction from the original binary may be represented by tens of instructions in the lifted code.
 - Lifted code does not contain the useful debug information that may allow one to view the source code associated with some bits of machine code.

**Opportunities**

 - The [`RegState`](/mcsema/Arch/X86/Runtime/State.h) is stored in memory. The advantage to this is that one can set data breakpoints (hardware watchpoints) on individual registers in the state structure. This is incredibly useful if you have a [time-travelling debugger](http://undo.io/products/undodb/).
 - Lifted bitcode can be instrumented using the LLVM toolchain. Some useful-for-debugging instrumentations come built-in to `mcsema-lift`. 

#### Built-in instrumentation

`mcsema-lift` comes with two useful instrumentations that can help during debugging: `-add-breakpoints` and `-add-reg-tracer`.

### Breakpoint functions with `-add-breakpoints`

One of the aforementioned drawbacks when trying to debug lifted code is that it is more verbose. This verbosity makes things hard if you're trying to debug the translation of a specific instruction in the original binary, or if you're trying to pause execution at a specific spot.

That is why there is the `-add-breakpoints` option. The idea is that, just as you can say `b *0x402a00` to set a breakpoint on an instruction in the original binary, you can also do `b breakpoint_402a00` to set a breakpoint on the location of an "original instruction", but in the lifted binary.

Native code | Lifted code with breakpoint functions
:----------:|:-------------------------:
![Native code](images/breakpoint_orig_code.png) | ![Lifted code](images/breakpoint.png)

On the left we see two instructions from the native code. On the right, we see the lifted code associated with the first and part of the second native instruction. Interspersed between the two are the `breakpoint_` functions. These breakpoint functions are "serializing" instructions. We can be certain that the `RegState` structure is in a consistent state at each call to a `breakpoint_` function. That is, the contents of the `RegState` struct at `breakpoint_402a00` in the lifted code should mostly match the native register state at `0x402a00` in the original binary.

#### Example

Here's an example of using the `print-reg-state-64` GDB command in conjunction with the breakpoint feature.

First, we set a breakpoint at `breakpoint_402a00` in `/tmp/ls_lifted`. The lifted state at this point will correspond to the native state at `0x402a00` in `/bin/ls`.

```
(gdb) b breakpoint_402a00
Breakpoint 1 at 0x4f9160
```

Second, run the program until the breakpoint is hit.

```
(gdb) r
Starting program: /tmp/ls_lifted 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Breakpoint 1, 0x00000000004f9160 in breakpoint_402a00 ()
```

We're now stopped at the `breakpoint_402a00` and can inspect the values of the `RegState` structure.

```
(gdb) print-reg-state-64
             emulated                   native
rip     0x0000000000402a00        0x00000000004f9160
rax     0x000000000040399d        0x000000000040399d
rbx     0x0000000000000000        0x8000000000000000
rcx     0x0000000000000000        0x0000000000000000
rdx     0x00007fffffffddb8        0x00007fffffffddb8
rsi     0x00007fffffffdda8        0x00007fffffffdda8
rdi     0x0000000000000001        0x00007ffff7ebb810
rbp     0x0000000000515620        0x00007ffff7fbba30
rsp     0x00007fffffffdcc8        0x00007ffff7fbb978
r8      0x0000000000515690        0x0000000000515690
r9      0x00007ffff7de78e0        0x00007ffff7de78e0
r10     0x0000000000000846        0x0000000000000846
r11     0x00007ffff717b740        0x00007ffff717b740
r12     0x0000000000402670        0x0000000000402670
r13     0x00007fffffffdda0        0xde7accccde7acccc
r14     0x0000000000000000        0x0000000000000000
r15     0x0000000000000000        0x00007ffff7ebb810
(gdb) 
```

Here, lets go see what things look like in the original `/bin/ls` program at the same place.

```
(gdb) b *0x402a00
Breakpoint 1 at 0x402a00
(gdb) r
Starting program: /bin/ls 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000000000402a00 in ?? ()
(gdb) info reg
rax            0x402a00 4205056
rbx            0x0  0
rcx            0x0  0
rdx            0x7fffffffddb8 140737488346552
rsi            0x7fffffffdda8 140737488346536
rdi            0x1  1
rbp            0x413be0 0x413be0
rsp            0x7fffffffdcc8 0x7fffffffdcc8
r8             0x413c50 4275280
r9             0x7ffff7de78e0 140737351940320
r10            0x846  2118
r11            0x7ffff780c740 140737345800000
r12            0x4049a0 4213152
r13            0x7fffffffdda0 140737488346528
r14            0x0  0
r15            0x0  0
rip            0x402a00 0x402a00
```

Things won't perfectly match up, especially near the beginning of the execution (`402a00` is the entrypoint of the `main` function). Nonetheless, the *essential* parts will match up -- those that affect later computations and control-flow.

This is a nifty way of visually seeing if things match up with your expectations. Though, not everything is printed out at this point. For example, if you're observing that lifted execution goes one way, while native execution goes the other, then you may want to inspect the `EFLAGS` register to see what's going on. There's a command for that too!

```
(gdb) print-flags-64
eflags [PF AF ZF ]
```

#### Advanced usage

This part depends on you having a reversible debugger. Some options are [UndoDB](http://undo.io/products/undodb/), [Mozilla rr](https://github.com/mozilla/rr), or using the plain-old (and slow) [GDB reverse debugger](https://www.gnu.org/software/gdb/news/reversible.html) (there is also some Valgrind support for this).

The below example is based on using UndoDB. This example is contrived, but shows of a successful workflow for hunting down bugs.

Let's say we're in `sub_40eca0` and we want to know who initializes the value of first argument, stored in register `rdi`. We can see from the picture on the right that the function `sub_40eca0` is called from many places.

Function `sub_40eca0` using `rdi` | Callers of `sub_40eca0`
---------------------------------:|:------------------------ 
![Function using RDI](images/rdi_in_called_function.png) | ![Function using RDI](images/sources_of_rdi.png)

Now we get to take advantage of one of our opportunities: we can set data breakpoints on registers in the `RegState` structure! Let's go find the source of `rdi` given a call to `sub_40eca0`.

First, we get the address of `rdi` within the `RegState` structure.
```
(gdb) addr-of-rdi
&(RegState::rdi) = 0x00007ffff7ebb840
```

Then, we set a hardware watchpoint, and reverse-execute.

```
(undodb-gdb) reverse-continue
Continuing.
Hardware watchpoint 1: *0x00007f0334483840

Old value = -1878107376
New value = 32207024
0x00000000004d27eb in sub_40eca0 ()
```

Great! You can now investigate the register state here with `print-reg-state-64`, and potentially work your way back by setting more watchpoints. It's useful to coordinate this workflow with IDA Pro or Binary Ninja to visually see where you are.

One reason why this approach can be successful is that it can be applied from where the bug occurs, and used to work back from there. This example was contrived; a better solution would have been to look at a backtrace on entry to `sub_40eca0` to see who the caller is. This technique is more effectively applied when working backward through complex control flows.

### Register tracing with `-add-reg-tracer`

A second option to `mcsema-lift` is `-add-reg-tracer`. This will inject function calls before every lifted instruction (similar to `-add-breakpoints`). The called function prints out the values of the general purpose registers stored in the `RegState` structure.

#### Collecting lifted traces

The first step to collecting a trace is to disassemble and lift a program. Our program of choice is `/bin/ls`. There is a bug in the lifted code when we run the lifted program with the `--recursive` option, and we're going to diagnose it.

First, disassemble the program.

```shell
mcsema-disass --arch amd64 --os linux --disassembler /opt/ida-6.9/idal64 --output /tmp/ls.cfg --binary /bin/ls --log_file /dev/stderr --entrypoint main
```

Then, lift it, adding in the `-add-reg-tracer` option.

```shell
mcsema-lift --arch amd64 --os linux --cfg /tmp/ls.cfg --output /tmp/ls.bc --entrypoint main -add-reg-tracer
```

Finally, compile it back to a program.

```shell
clang-3.8 -O3 -o /tmp/ls_lifted /home/pag/Code/mcsema/generated/ELF_64_linux.S /tmp/ls.bc -lpthread -ldl -lpcre /lib/x86_64-linux-gnu/libselinux.so.1
```

Now we can run it and see an example of the output.

```shell
pag@sloth:~/Code/mcsema/tools/regtrace$ /tmp/ls_lifted --recursive
RIP=402a00 RAX=4039ed RBX=0 RCX=0 RDX=7fffc67546b0 RSI=7fffc6754698 RDI=2 RSP=7fffc67545b8 RBP=4e9b60 R8=4e9bd0 R9=7f0bc4b178e0 R10=846 R11=7f0bc3eab740 R12=4026c0 R13=7fffc6754690 R14=0 R15=0
RIP=402a02 RAX=4039ed RBX=0 RCX=0 RDX=7fffc67546b0 RSI=7fffc6754698 RDI=2 RSP=7fffc67545b0 RBP=4e9b60 R8=4e9bd0 R9=7f0bc4b178e0 R10=846 R11=7f0bc3eab740 R12=4026c0 R13=7fffc6754690 R14=0 R15=0
...
Segmentation fault
```

Great, we can see the bug mentioned above: the execution halts at a segmentation fault. The other thing we can see is that the output is quite verbose! The produced output lets you see, at an instruction granularity, how the register state changes. It's especially useful as a way of debugging control-flow divergences between what should have happened in the original binary, versus what did happen in the lifted binary.

Let's make a copy of this trace for later.

```shell
/tmp/ls_lifted --recursive >/tmp/lifted_trace
Segmentation fault
```

So we have a trace of the lifted program, and we'd like to discover where it diverges relative to the original program. What do we do?

#### Collecting native traces with PIN

One way to drill down on divergences is by comparing the lifted trace with a ground truth: a trace recorded from a native program execution. We can do this with the [`regtrace` PIN tool](/mcsema/tools/regtrace/README.md). The first step is to [download and install PIN](https://software.intel.com/en-us/articles/pintool-downloads) before we can use the PIN tool. 

The next step to using the PIN tool is to build it!

```shell
cd tools/regtrace
export PIN_ROOT=/opt/pin-3.2-81205-gcc-linux/
./build.sh
```

Then we'll run it and collect a trace.

```shell
${PIN_ROOT}/pin -t obj-intel64/Trace.so -entrypoint 0x402a00 -- /bin/ls --recursive >/tmp/native_trace
```

Note that the address `0x402a00` passed to `-entrypoint` is the address of `main` in the original binary. We specified `main` as the entrypoint to the program when disassembled and lifted it.

Now we've got the two traces and so we can diff them to drill down on discovering the divergence.

There are a few gotchas when comparing traces.

##### Gotcha #1: External calls

The first gotcha is calls to externals, like `strlen`. In native code, there will be a call to a stub function that goes to `strlen`. The lifted code will not have lifted these stubs, and so will not emulate the instructions of the stubs. The effect is that there will be extra instructions printed out from the `regtrace` tool that are absent from the lifted code.

##### Gotcha #2: Spurious differences

The second gotcha is spurious differences between the traces. There are likely to be a lot of these, especially when the original binary calls out to a shared library, and then execution returns back into the original binary. Many register values on return from the library code, but in the lifted program, will have different values that what is recorded by `regtrace`.

Another example of spurious differences relate to `REP`-prefixed instructions. The first example is repeated string instructions, e.g. `rep stos`. In a native trace, each repeated iteration will produce a single line of output. In the lifted trace, there will only be one line.

##### Gotcha #3: Huge traces

The final gotcha is huge traces. It is often useful to narrow the scope of what is diffed. Our current example produces a segmentation fault when running `/tmp/lifted_ls --recursive`, but this happens after some file information is printed. So we'll start by diffing a prefix of the trace, using some program's output (a file name) as a starting point.

First we find the line in the traces containing the word `Trace`, which is part of the name of one of the listed files, `Trace.cpp`. Here's what we see:

```shell
pag@sloth:~/Code/mcsema/tools/regtrace$ grep -n Trace /tmp/native_trace 
16156:Trace.cpp
16159:Trace.o
16160:Trace.so
16163:Trace.o
16164:Trace.so
pag@sloth:~/Code/mcsema/tools/regtrace$ grep -n Trace /tmp/lifted_trace 
8847:Trace.cppRIP=4054cf RAX=9 RBX=9 RCX=7ffb9e7aa620 RDX=0 RSI=1 RDI=7ffd7755b190 RSP=7ffd7755b150 RBP=7ffd7755d1d0 R8=0 R9=0 R10=2000 R11=7ffb9e406740 R12=0 R13=1bebe80 R14=1bde040 R15=0
11132:Trace.oRIP=4054cf RAX=7 RBX=7 RCX=7ffb9e7aa620 RDX=0 RSI=1 RDI=7ffd7755b190 RSP=7ffd7755b150 RBP=7ffd7755d1d0 R8=0 R9=0 R10=2000 R11=7ffb9e406740 R12=0 R13=1bebec0 R14=1bde040 R15=0
11798:Trace.soRIP=4054cf RAX=8 RBX=8 RCX=7ffb9e7aa620 RDX=0 RSI=1 RDI=7ffd7755b190 RSP=7ffd7755b150 RBP=7ffd7755d1d0 R8=0 R9=0 R10=2000 R11=7ffb9e406740 R12=0 R13=1bebe80 R14=1bde040 R15=0
```

Now lets chop down the traces using those first line numbers as a guide.

```shell
pag@sloth:~/Code/mcsema/tools/regtrace$ head -n 8847 /tmp/lifted_trace >/tmp/lifted_trace_short 
pag@sloth:~/Code/mcsema/tools/regtrace$ head -n 16156 /tmp/native_trace >/tmp/native_trace_short 
```

Great, we can diff these. Still though, there are thousands of lines, and due spurious differences, we're still stuck with everything looking different. We can take a new approach though. Let's focus on the program counters first, and look for the first significant control-flow divergence, then work back from there.

```shell
pag@sloth:~/Code/mcsema/tools/regtrace$ grep -oP '^RIP[^ ]+' /tmp/native_trace | head -n 16156  >/tmp/native_trace_short
pag@sloth:~/Code/mcsema/tools/regtrace$ grep -oP '^RIP[^ ]+' /tmp/lifted_trace | head -n 8847  >/tmp/lifted_trace_short
```