#FAQ

In this document we are going to talk about some common issues/questions user face.

## McSema produced some warning/errors

Unfortunately McSema sometimes log perhaps important information in form of a warning or error.
As a rule of thumb, if mcsema produced a bitcode the lift process went okay. This does however
*not mean* that the program was lifted correctly, as there may have been error during
CFG production (`mcsema-disass`) or there are some unknown instructions (while `remill`
contains a lot of semantics function there are some more exotic it may not have).

Each of the following warnings *should* be safe:

```
1) Cannot find target of instruction at X; the static target Y is not associated with a lifted subroutine, and it does not have a known call target.
2) Adding missing block X in function sub_4003d0_Y as a tail call to __remill_error
```

`2)` may indicate an error, however it often happens frontend marks some area as function
even though it really is not. McSema then lifts this function but it is typically
ill formed - error is issued. However, this function is never called, so it does not
matter.

## ERROR Uknown opcode

Remill could not find semantic function for given instruction. Two most common reasons are:
    - there is no implementation yet (PR are welcomed)
    - XED specific name for the instruction changed and `remill` expects the old name
Latter case is easy to fix, if you are unsure open an issue.

## Produced bitcode contains inline assembler and I would like "pure" llvm bitcode

Pass `--explicit-args` to the `mcsema-lift`. This option removes assembly stubs with
their approximate bitcode implementations (in corner cases can lead to fault when recompiling).
You will also need to specify all external functions via `--abi-libs`.

## McSema uses wrong types for external functions

There is no way for McSema to know about types of well-known externals unless someone tells
it about it. Command line flag `--abi-libs` does exactly that. It accepts comma separated list
of llvm bitcode files e.g `--abi-libs X.bc,Y.bc` and it copies all function prototypes from it.
So if the `X.bc` contains `void @ext_foo( i64, i8 * )` and McSema sees call to external `ext_foo`
in the binary, it can give `ext_foo` better type and reconstruct the call site more precisely.

## Where can I find lifted function?

Each internal function is lifted to a function with special name. The naming schema for internal
function is defined as follows: `sub_` + address in the binary + name (if it can be retrieved).

## Where can I find local variables?

Unfortunately McSema cannot lift local variables (even with debug info present it requires
non-trivial analysis) and since the stack is one chunk of memory (really big array) you
will need to do some analysis yourself.
However this is a problem that may be tackled in the future, come check later!

## Where can I find global variables?

Same as for local variables, only instead of stack you need to search in global variables
that represents original data segments instead of stack.

## Can McSema handle self-modifying code?

McSema lifts binary statically, therefore no (you probably want some other remill-based tool).

## I cannot build McSema on Windows because x, y, z reason

TOOD

## I cannot build Dyninst frontend because it produces some compile time errors in the mcsema code

Are you sure you are using Dyninst version v9.3.2? If you do not want to bother, you can try docker
build (currently work in progress).

## Can I investigate content of the CFG file?

CFG files are currently implemented as protobuf files, which are binary blobs. You would need to
manually tweak McSema sources to print it (rather easy modification).

## Lifted bitcode contains a lot of functions that were not present in my original source code

McSema lifts the whole binary which includes also pre-`main` routines (such as `__libc_csu_init`
or `_start`)
See: [Issue 517](https://github.com/lifting-bits/mcsema/issues/517)

## Recompilation of lifted bitcode fails with: "redefinition of ..."

There are some parts of pre-`main` routine that gets linked every time a program is compiled
(like `_start`). So they are linked first time when the binary is produced and when it is lifted,
they are lifted as well. Unfortunately they are linked again when the lifted code is recompiled,
which ends up producing a linker error.

McSema frontends try to keep a list of these function, so they can lift them in a way that does
not interfere with linker. Either add it yourself (if you grep for `_start` you will find it
rather easily) or open a PR and someone will hopefully look into it for you.

## Produced bitcode is confusing

Well McSema tries to simulate the binary program, so there is no general way around verbose bitcode.
That said there are some cases when a more compact and human-friendly bitcode can be produced, see
for example `anvill`.
After a while you will get used to it anyway, there is no magic happening.

## Recompiled bitcode crashes

Well there is a lot of possible reasons, see the rest of reading material in the repo and if
you still have no idea visit empire-hacking slack, someone may lend you a hand there.
