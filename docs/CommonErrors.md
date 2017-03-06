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
