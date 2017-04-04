# Machine code to bitcode: the life of an instruction

This document describes how machine code instructions are lifted into LLVM bitcode. It should provide a detailed, inside-out overview of how McSema performs binary translation. This document omits some important steps, so consulting the [Navigating the code](NavigatingTheCode.md) document will be helpful.

### Running example

This document will use the instructions in the following basic block as a running example.

![Sample basic block](images/instruction_life_block.png)

## Step 1: CFG protocol buffer representation

The first step to lifting involves getting the machine code instructions of some binary file into a format the McSema understands. These files are generated with the help of external tools for program disassembly (IDA Pro) so that McSema doesn't need to understand the many executable file formats.

The file format used by McSema is a [CFG protocol buffer](/mcsema/CFG/CFG.proto). This file is produced using the [`mcsema-disass`](/mcsema/tools/mcsema_disass) tool. The CFG file for the above code block contains the following data.

```protobuf
Module {
  internal_funcs = [
    Function {
      entry_address = 0x804b7a3;
      symbol_name = "sub_804b7a3";
      local_noreturn = true;
      blocks = [
          Block {
            base_address = 0x804b7a3;
            block_follows = [ ];
            insts = [

              // mov    eax, 0x1
              Instruction {
                inst_addr = 0x804b7a3;
                inst_len = 5;
                inst_bytes = "\xb8\x01\x00\x00\x00";
              },

              // push   ebx
              Instruction {
                inst_addr = 0x0804b7a8;
                inst_len = 1;
                inst_bytes = "\x53";
              },

              // mov    ebx, dword [esp+0x8]
              Instruction {
                inst_addr = 0x0804b7a9;
                inst_len = 4;
                inst_bytes = "\x8b\x5c\x24\x08";
              },

              // int    0x80
              Instruction {
                inst_addr = 0x0804b7ad;
                inst_len = 2;
                inst_bytes = "\xcd\x80";
              } ];
          } ];
    } ];
  ...
}      
```

## Step 2: Lifting to bitcode

The second step, which is really a few steps, is to decode the CFG file and produce one LLVM bitcode function for every `Function` message into the CFG file. Below is a portion of the *unoptimized* bitcode produced for the above function.

```llvm
; Function Attrs: noinline
define void @sub_804b7a3(%RegState*) #1 {
entry:
  %EIP_write = bitcast i32* %RIP_read to i32*
  %EIP_read = bitcast i32* %EIP_write to i32*
  ...
  %EAX_read = bitcast i32* %EAX_write to i32*
  %AX_write = bitcast i32* %EAX_read to i16*
  %AX_read = bitcast i16* %AX_write to i16*
  %AL_write = bitcast i16* %AX_read to i8*
  %AL_read = bitcast i8* %AL_write to i8*
  %AH_write = getelementptr inbounds i8, i8* %AL_read, i32 1
  %AH_read = bitcast i8* %AH_write to i8*
  ...
  %EBX_write = bitcast i32* %RBX_read to i32*
  %EBX_read = bitcast i32* %EBX_write to i32*
  ...
  %ESP_write = bitcast i32* %RSP_read to i32*
  %ESP_read = bitcast i32* %ESP_write to i32*
  %SP_write = bitcast i32* %ESP_read to i16*
  %SP_read = bitcast i16* %SP_write to i16*
  ...
  ...
  %ZF_write = getelementptr inbounds %RegState, %RegState* %0, i32 0, i32 20
  %ZF_read = bitcast i8* %ZF_write to i8*
  %SF_write = getelementptr inbounds %RegState, %RegState* %0, i32 0, i32 21
  ...
  %ST0_write = getelementptr inbounds %RegState, %RegState* %0, i32 0, i32 24
  %ST0_read = bitcast x86_fp80* %ST0_write to x86_fp80*
  ...
  %XMM15_read = bitcast i128* %XMM15_write to i128*
  br label %block_80483bc

block_804b7a3:                                    ; preds = %entry
  store volatile i32 134513596, i32* %EIP_write
  store volatile i32 1, i32* %EAX_write
  store volatile i32 134513601, i32* %EIP_write
  %1 = load i32, i32* %EBX_read
  %2 = load i32, i32* %ESP_read
  %3 = sub i32 %2, 4
  %4 = inttoptr i32 %3 to i32*
  store i32 %1, i32* %4
  store volatile i32 %3, i32* %ESP_write
  store volatile i32 134513602, i32* %EIP_write
  %5 = load i32, i32* %ESP_read
  %6 = add i32 %5, 8
  %7 = inttoptr i32 %6 to i32*
  %8 = load i32, i32* %7
  store volatile i32 %8, i32* %EBX_write
  store volatile i32 134513606, i32* %EIP_write
  %9 = load i32, i32* %EAX_read
  %10 = load i32, i32* %EBX_read
  %11 = load i32, i32* %ECX_read
  %12 = load i32, i32* %EDX_read
  %13 = load i32, i32* %ESI_read
  %14 = load i32, i32* %EDI_read
  %15 = load i32, i32* %EBP_read
  %16 = call i32 (i32, ...) @syscall(i32 %9, i32 %10, i32 %11, i32 %12, i32 %13, i32 %14, i32 %15)
  store volatile i32 %16, i32* %EAX_write
  unreachable
}
```

The produced LLVM functions have a predictable structure. They are named according to the `entry_address` field in the `Function` message. The `entry_address` of our example function is `0x804b7a3`, and so the lifted function is named `sub_804b7a3`.

All lifted functions accept a single argument: a pointer to a [`RegState`](/mcsema/Arch/X86/Runtime/State.h) structure. The `entry` block of the function is filled with a series of `getelementptr` and `bitcast` instructions. These instruction index into the fields of the `RegState` structure.

Each field in the `RegState` structure produces at least two variables in the bitcode. These register variants are created by the `ArchAllocRegisterVars` function. In the case of X86, this architecture-neutral function is implemented using the [`X86AllocRegisterVars`](/mcsema/Arch/X86/Register.cpp) function.

Some registers have more derived registers than others. On one end, we have the FPU stack registers like `RegState::ST0` that have only one `_read` and `_write` variant. At the other extreme, we have `RegState::RAX`, which is associated with `RAX_read`, `RAX_write`, `EAX_read`, `EAX_write`, `AX_read`, `AX_write`, `AH_read`, `AH_write`, `AL_read`, and `AL_write`. All of the variants are made available in every lifted function prologue, and a subset of them will usually be used by the semantics bitcode.

We can see the `_read` and `_write` variants of the register variables in action below in the translation of the `push ebx` instruction. This bitcode is produced using the [`doPushR`](/mcsema/Arch/X86/Semantics/Stack.cpp) function.

```llvm
  %1 = load i32, i32* %EBX_read           ; read EBX
  %2 = load i32, i32* %ESP_read           ; read ESP
  %3 = sub i32 %2, 4                      ; decrement ESP
  %4 = inttoptr i32 %3 to i32*            ; cast ESP to a pointer
  store i32 %1, i32* %4                   ; store EBX to the stack
  store volatile i32 %3, i32* %ESP_write  ; write back the new ESP
```

The `_read` and `_write` variants aren't very important for 32-bit code, but come up a lot in 64-bit code. For example, a write to `EAX` in 64-bit code clears the high 32-bits of the `RAX` register. Therefore, in 64-bit code, the `EAX_write` variable is a pointer to the whole 64-bit value of `RegState::RAX`.

Later on we see a call to the `syscall` function. This was generated in the semantics translation function [`doInt`](/mcsema/Arch/X86/Semantics/Misc.cpp) using the following code:.

```c++
  ...
  if (0x80 == interrupt_val && llvm::Triple::Linux == os) {
    ...
    auto syscall_func = M->getOrInsertFunction("syscall", syscall_func_ty);

    std::vector<llvm::Value *> args = {
      R_READ<32>(b, llvm::X86::EAX),  // %9 = load i32, i32* %EAX_read
      R_READ<32>(b, llvm::X86::EBX),  // %10 = load i32, i32* %EBX_read
      R_READ<32>(b, llvm::X86::ECX),  // %11 = load i32, i32* %ECX_read
      R_READ<32>(b, llvm::X86::EDX),  // %12 = load i32, i32* %EDX_read
      R_READ<32>(b, llvm::X86::ESI),  // %13 = load i32, i32* %ESI_read
      R_READ<32>(b, llvm::X86::EDI),  // %14 = load i32, i32* %EDI_read
      R_READ<32>(b, llvm::X86::EBP),  // %15 = load i32, i32* %EBP_read
    };

    // %16 = call i32 (i32, ...) @syscall(i32 %9, ..., i32 %15)
    auto ret = llvm::CallInst::Create(syscall_func, args, "", b);

    // store volatile i32 %16, i32* %EAX_write
    R_WRITE<32>(b, llvm::X86::EAX, ret);

    return ContinueBlock;
  }
```

We can see parallels between the bitcode above and the C++ code implementing the semantics of the `int 0x80` instruction. First, this instruction is interpreted as a system call, but only on Linux. Second, we can see that every call to the `R_READ` function is associated with a `load` from a `_read`-suffixed register variable. Third, we can see that a call to the `R_WRITE` function is associated with a `store` to a `_write`-suffixed register variable.

The translation function ends with a `return ContinueBlock`, which instructions McSema to keep lifted the remaining instructions of the basic block. Yet we see an `unreachable` instruction in the bitcode. Why?

`mcsema-disass` was smart enough to recognize that this particular `int 0x80` system call does not return. Therefore, it marked the `Function` message with `local_noreturn` as `true`. The `Block` containing the `int 0x80` has no successors (`block_follows` is empty), and the `int 0x80` is the last instruction, and so McSema recognized that it should add in an `unreachable` instruction to mark this block as not returning.

### Optimizing the bitcode

The bitcode produced for this particular example expresses the semantics clearly, and is not overly complicated. This particular example did not involve any "interesting" instructions.

Many x86 instructions implicitly modify the [`FLAGS`](https://en.wikipedia.org/wiki/FLAGS_register) register, and McSema models these changes in the bitcode. Often there will be a series of such instructions, and so those behind-the-scenes flag register computations will be "dead."

```assembly
add eax, 1
sub ebx, 1
```

In the above example, both `sub` instructions modify the x86 `FLAGS` register. The updates to the flags register performed by `add` instruction are clobbered by those performed by the `sub` instruction. Eliminating these unnecessary computations can be tricky and involves complex alias analysis.

`mcsema-lift` includes a sophisticated whole-program dead register computation elimination optimization. This optimization, which can be disabled with `-disable-global-opt`, will annotate the lifted bitcode with LLVM's `!alias.scope` and `!noalias` metadata, and it will perform load-forwarding, dead-store elimination, and `store-to-load` forwarding. 

## Closing remarks

This document gives a low level view as to what the machine code will look like as bitcode. This is only part of the picture, though. The instructions in our example did not perform any complex control-flow, register computations, or access to global data structures. Not to worry though, McSema also handles these complications.
