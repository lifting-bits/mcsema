# Limitations

The McSema toolset currently has some limitations which limit what programs it is able to translate to LLVM.

## Building and Running

McSema is tested primarily on 64-bit Linux and secondarily on 64-bit Windows. While McSema should build and run on macOS, it is not explicitly tested and may not work.

Where McSema runs is independent of the binaries it can process (e.g. the Windows version can translate Linux binaries, and vice versa).

## Control Flow Recovery

McSema is desiged to translate compiler-generated binaries. It will probably not handle packed, encrypted, or otherwise obfuscated code.

## Code / Data / Constant mismatches

McSema's CFG recovery depends on IDA Pro being accurate. Sometimes its not. We attempt to work around common issues in our scripts, but can't guarantee that every binary works.

### Self-modifying code

The translator is not designed to accommodate self-modifying code directly. An approach is possible to model its effects, where the modifications are described in a native control flow graph as branches to a new basic block, however this could be difficult to construct.

### Raw Binaries

We do not support raw binary blobs (e.g. firmware). Operating on blobs should be possible via a custom control flow recovery solution, but our default scripts only work on PEs and ELFs.

## Translation

### Instruction Support

McSema uses Remill for lifting machine code instructions to LLVM bitcode. As Remill's support grows, so does McSema's. At the time of this writing, Remill supports a large number of X86 features, include arithmetic/integer, x87 floating point, SSE, and AVX instructions. Remill also supports a growing number of AArch64 instructions.

McSema will call a special Remill function named `__remill_sync_hyper_call` when it lifts unsupported instructions, or to model the effects of some complex instructions. For example, it is not practical to encode the effects of X86's `cpuid` or `rdtscp` instructions directly in the semantics.

### Exceptions

McSema currently pretends that exceptions do not exist; if they do, then it assumes something else will handle them correctly.

The translation problem of exception handling is difficult, with different approaches having tradeoffs between accuracy and speed. The most conservative approach is to do explicit exception checks for every possible exception an instruction can generate. The least conservative approach is to ignore exceptions and hope they are generated in the translated code.

The most conservative approach will greatly increase code size and reduce speed. The checks for exceptional conditions cannot be optimized out, as the values of instruction operands are not known a-priori. The least conservative approach could miss exception, and presents a context problem when exceptions happen. The exception will occur in native code, and the native exception handler must translate this to a register context and call the original exception handler. This is more difficult than a simple store/spill, since default except handlers perform stack unwinding to determine where to transfer control flow. One would need to ensure the unwinding code worked on the context that was given to the original exception handler.

### External Function ABIs

We assume that external function ABIs are the default for the platform and processor combination of the target. While the ABI of internal functions inside a program does not matter, the ABI of external functions has to conform to the specification for the target platform.

External functions that take floating point arguments, or return floating point values are not yet supported, but there is no technical limitation peventing it; the glue code enabling this has just not been written. Pull requests are welcome.

### x87 FPU

Appliations that use the x87 FPU should run and report similar results, although sometimes at a lower precision. The x87 FPU is modelled using operations on `double` (64-bit floating point numbers), whereas the real hardware operates on `long double`s (80-bit floating point). Operating on `double`s was a deliberate design decision to improve the portability of the lifted bitcode.

#### Precision and Rounding Control

Lifted bitcode does not explicitly represent the current FPU precision or rounding modes. Instead, it queries/controls the current FPU precision via standardized libc functions.

#### Last Instruction Pointer

The last instruction pointer of the FPU is not modelled. Anything that reads this field and performs logic on it is self-referential code that we currently do not support.

### Memory Segmentation

McSema supports common segment prefixes that are used with TLS code, such as `fs` and `gs`. Setting the value of a segment register is not directly supported, but instead handled via `__remill_sync_hyper_call`.
