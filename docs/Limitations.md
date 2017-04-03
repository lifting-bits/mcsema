# Limitations 

The mcsema toolset currently has some limitations which limit what programs it is able to translate to LLVM. 

## Building and Running

Mcsema is tested primarily on 64-bit Linux and secondarily on 64-bit Windows. While mcsema should build and run on MacOS, it is not explicitly tested and may not work.

Where mcsema runs is independent of the binaries it can process (e.g. the Windows version can translate Linux binaries, and vice versa).

## Control Flow Recovery

Mcsema is designed to translate compiler-generated binaries. It will probably not handle packed, encrypted, or otherwise obfuscated code.

## Code / Data / Constant mismatches

Mcsema's CFG recovery depends on IDA Pro being accurate. Sometimes its not. We attempt to work around common issues in our scripts, but can't guarantee that every binary works.

### Self-modifying code

The translator is not designed to accommodate self-modifying code directly. An approach is possible to model its effects, where the modifications are described in a native control flow graph as branches to a new basic block, however this could be difficult to construct. 

### Raw Binaries

We do not support raw binary blobs (e.g. firmware). Operating on blobs should be possible via a custom control flow recovery solution, but our default scripts only work on PEs and ELFs.

## Translation

### Instruction Support

While the vast majority of integer operations and many floating point operations are supported, there are many x86 instructions left. The following broad categories of instructions have support in internal register context structures, but the translations are incomplete:

- Floating Point support is incomplete, but handles a lot of regular use-cases.
- SSE 1/2/3/4 is incomplete, but handles a lot of regular use-cases.
- AVX is not supported
- AESNI, SHA, RDRAND, MPX, SGX instruction sets are not supported

The following categories of instructions do not have internal register context support:

- Debug Register Modification
- Privileged Instructions
- AVX

### `CPUID`

Our support for CPU self-identification is [very limited](https://github.com/trailofbits/mcsema/blob/master/mcsema/Arch/X86/Semantics/Misc.cpp). Support only extends to ensure applications that rely on `CPUID` to select a fast code path still run.

### Exceptions

Mcsema currently pretends that exceptions do not exist; if they do, it assumes something else will handle them correctly.

The translation problem of exception handling is difficult, with different approaches having tradeoffs between accuracy and speed. The most conservative approach is to do explicit exception checks for every possible exception an instruction can generate. The least conservative approach is to ignore exceptions and hope they are generated in the translated code.

The most conservative approach will greatly increase code size and reduce speed. The checks for exceptional conditions cannot be optimized out, as the values of instruction operands are not known a-priori. The least conservative approach could miss exception, and presents a context problem when exceptions happen. The exception will occur in native code, and the native exception handler must translate this to a register context and call the original exception handler. This is more difficult than a simple store/spill, since default except handlers perform stack unwinding to determine where to transfer control flow. One would need to ensure the unwinding code worked on the context that was given to the original exception handler.

### External Function ABIs

We assume that external function ABIs are the default for the platform and processor combination of the target. While the ABI of internal functions inside a program does not matter, the ABI of external functions has to conform to the specification for the target platform. 

External functions that return floating point values are not yet supported, but there is no technical limitation preventing it; the glue code enabling this has just not been written. Pull requests are welcome.

### FPU

Applications that use the x87 FPU should run and report similar results. They are not currently guaranteed to report identical results. Better FPU support is a long term ongoing process.

#### Testing/Polishing of Precision Control 

Precision control needs much more testing to verify it works. Some instructions may also need to ignore precision control and always operate on double extended precision.

#### Last Instruction Pointer 

We can only provide a pointer to the block that we represent a floating point instruction with, not the actual FPU instruction that LLVM emits. Anything that reads this field and performs logic on it is self-referential code that we currently do not support.

#### Segments 

Mcsema supports common segment prefixes that are used with TLS code, such as `fs` and `gs`. Setting the value of a segment register is not a supported operation.

#### Rounding and Precision Control

Rounding control and other FPU settings are not well supported.

