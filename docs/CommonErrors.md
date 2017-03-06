# Common McSema Errors

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
