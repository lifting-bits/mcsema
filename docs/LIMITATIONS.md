# Limitations 

The mc-sema toolset currently has some limitations which limit what programs it is able to translate to LLVM. 

## Control Flow Recovery

### Self-modifying code

The translator is not designed to accommodate self-modifying code directly. An approach is possible to model its effects, where the modifications are described in a native control flow graph as branches to a new basic block, however this could be difficult to construct. 

## Translation

### Instrution Support

While the vast majority of integer operations and many floating point operations are supported, there are many x86 instructions left. The following broad categories of instructions have support in internal register context structures, but the translations are incomplete:

- Floating Point (some instructions still untranslated)
- SSE 1/2/3 (only MOVDQA currently translated)

The following categories of instructions do not have internal register context support:

- Debug Register Modifiction
- Privileged Instructions
- AVX

### Exceptions

The translation problem of exception handling is difficult, with different approaches having tradeoffs between accuracy and speed. The most conservative approach is to do explicit exception checks for every possible exception an instruction can generate. The least conservative approach is to ignore exceptions and hope they are generated in the translated code.

The most conservative approach will greatly increase code size and reduce speed. The checks for exceptional conditions cannot be optimized out, as the values of instruction operands are not known a-priori. The least conservative approach could miss exception, and presents a context problem when exceptions happen. The exception will occur in native code, and the native exception handler must translate this to a register context and call the original exception handler. This is more difficult than a simple store/spill, since default except handlers perform stack unwinding to determine where to transfer control flow. One would need to ensure the unwinding code worked on the context that was given to the original exception handler.

### FPU

#### Testing/Polishing of Precision Control 

Precision control needs much more testing to verify it works. Some instructions may also need to ignore precision control and always operate on double extended precision.

#### More Instruction Support

There are FPU instructions that are not currently supported. Luckily a large portion of them have LLVM intrinsics.

#### Last Instruction Pointer 

We can only provide a pointer to the block that we represent a floating point instruction with, not the actual FPU instruction that LLVM emits. Anything that reads this field and performs logic on it is self-referential code that we currently do not support. Another problem with implementing this is that the llvm blockaddress instruction only works for compiled bitcode, not JITted bitcode. As of LLVM 3.0, it will actually break the JITter.

#### Segments 

The Last Instruction pointer and the Last Data pointer also store a segment number in addition to the virtual address of the pointer. The default segments vary by operating system, and of course it is possible to use segment override prefixes. Currently mc-sema is not fully segment aware, but will correctly translate code that references FS and GS, for instance.

#### Rounding Control

LLVM does not provide a way to specify floating point rounding mode. We would have to manually round results based on the rounding control field.
