# Future Improvements

The following items are on the agenda for future development of `mc-sema`.

## Additional Instruction Translation

This is both the easiest and most obvious enhancement. The easiest to accomplish would be completing the integer instructions and floating point instructions.

## Specify Instruction Semantics directly in C

Currently instruction semantics for translation are written using the LLVM API to emit raw LLVM bitcode. This is very tedious for complex operations, and might become extraordinaritly difficult for complex vector operations. A possible alternative is to write instruction semantics in C, and use Clang to transalte these to LLVM bitcode.

## Stack variable recovery

Currently translated functions have no concept of stack variables vs. variables stored in global memory. In many cases, an automated analysis can determine which memory writes are to stack slots and can uniquely assign stack slots to the entire function flow. In cases where this can be done, functions can be simplified and made more amenable to analysis and transformation. 

