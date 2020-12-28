# Solving a Maze with KLEE and McSema

This walkthrough describes how to run KLEE on a simple Maze program. The
instructions here have been tested on Arch Linux and Ubuntu 20.04. Your mileage
may vary if you are using another operating system. What is unique about this
walkthrough is that it will show that KLEE runs equally well on lifted bitcode
produced from the same program compiled to x86-64 (amd64) and AArch64 (64-bit
ARMv8).

The program, [Maze.c](Maze.c), can be found in this directory, along with the
[binaries](bin) and [control-flow graph files](cfg) for the Maze program.

## The Maze

The Maze program presents its user with the following challenge: type in a
sequence of `w`, `s`, `a`, or `d` characters to guide the `X` through the maze
and reach the destination denoted by `#`.

The characters `w`, `s`, `a`, and `d` are used in place of the keyboard's arrow
keys, that is:

```
    +---+               +---+
    | w |               | ^ |
+---+---+---+  <=>  +---+---+---+
| a | s | d |       | < | v | > |
+---+---+---+       +---+---+---+
```

Initially, the program displays the maze, and asks the user to type in their
directions for how to complete it.

```
Maze dimensions: 11x7
Player position: 1x1
Iteration no. 0
Program the player moves with a sequence of 'w', 's', 'a' and 'd'
Try to reach the price(#)!
+-+---+---+
|X|     |#|
| | --+ | |
| |   | | |
| +-- | | |
|     |   |
+-----+---+
```

The winning directions for the maze are `ssssddddwwaawwddddssssddwwww`. The
winning output looks like this:

```
Player position: 9x2
Iteration no. 26. Action: w.
+-+---+---+
|X|XXXXX|#|
|X|X--+X|X|
|X|XXX|X|X|
|X+--X|X|X|
|XXXXX|XXX|
+-----+---+

You win!
Your solution <              ssssddddwwaawwddddssssddwwww>
```

Let's jump in and see if we KLEE, acting as the user, can win this maze!

## Running KLEE

### Step 0: Install McSema and IDA Pro

This walkthrough assumes that McSema and all its dependencies has been installed
on the machine. Please refer to the [main README](../../README.md) to see how to
set up McSema.

### Step 1: Install KLEE

We have provided a convenient [script](./scripts/build_klee.sh) for this
walkthrough. The script will build a version of KLEE that is compatible with
McSema. By default, the build sources will be placed in `./build` and the built
files will all be in `./installed`. You may change the variables within the
script to change the software versions and build/install locations.

```bash
git clone https://github.com/lifting-bits/mcsema.git
cd mcsema/examples/Maze
./scripts/build_klee.sh
```

The script by default builds KLEE with LLVM version 10. You can change the LLVM
version with an additional option. For now, only LLVM 9 and 10 are supported.

```bash
./scripts/build_klee.sh --llvm 10
```

### Step 2: Lift the Maze binaries

To lift a given binary to LLVM bitcode with McSema, we need to first disassemble
the binaries into [CFG files](./cfg), containing its control flow graph and
instruction information. You can do so on the provided binaries in `./bin` by
executing the `./scripts/disass.sh` script as follows, which invokes the
`mcsema-disass` utility, so please make sure it is in `PATH`.

```sh
./scripts/disass.sh --disassembler path_to_IDA_Pro
```

If you don't have IDA Pro installed, we've also provided the CFG files in
`./cfg`.

The second step is to lift the CFG files to LLVM IR bitcode. Use the [lifting
script](scripts/lift.sh). The script invokes `mcsema-lift-10.0` on the provided
CFG files in `./cfg`. (You might want to change it if you have different LLVM
version.)

```bash
./scripts/lift.sh
```

### Step 3: Run KLEE

We can run the KLEE using the following commands. If things work, there will be
a lot of funny looking output.

```bash
./installed/klee/usr/bin/klee \
    --simplify-sym-indices \
    --solver-backend=z3 \
    --solver-optimize-divides \
    --use-forked-solver \
    --use-independent-solver \
    --write-cov \
    --write-paths \
    --write-sym-paths \
    --write-test-info \
    --external-calls=all \
    --suppress-external-warnings \
    --posix-runtime \
    --libc=none \
    ./bc/maze.amd64.bc --sym-stdin 28
```

The output directory should be in the same directory as the target bitcode file.
You could also use the provided `./scripts/run-klee.sh` to save some screen
space from the options.

```bash
./scripts/run-klee.sh ./bc/maze.x86.bc --sym-stdin 28
./scripts/run-klee.sh ./bc/maze.amd64.bc --sym-stdin 28
./scripts/run-klee.sh ./bc/maze.aarch64.bc --sym-stdin 28
```

### Step 4: Example output

We know that the answer to the maze is `ssssddddwwaawwddddssssddwwww`, so we can
check to see if KLEE found the answer by running `ktest-tool` on all of the
`.ktest` files in the KLEE's output file directory (`klee-last` is a symlink to
the most recently produced output directory).

```bash
for f in ./bc/klee-last/*.ktest; do
    ./installed/klee/usr/bin/ktest-tool $f | grep ssssddddwwaawwddddssssddwwww &>/dev/null
    if [ $? -eq 0 ]; then
        FOUND_TEST=$f
    fi
done
./installed/klee/usr/bin/ktest-tool $FOUND_TEST
```

The output we get should be something like the following:

```
ktest file : './bc/klee-last/test000376.ktest'
args       : ['<...>/bc/maze.amd64.bc', '--sym-stdin', '28']
num objects: 3
object 0: name: 'stdin'
object 0: size: 28
object 0: data: b'ssssddddwwaawwddddssssddwwww'
object 0: hex : 0x73737373646464647777616177776464646473737373646477777777
object 0: text: ssssddddwwaawwddddssssddwwww
object 1: name: 'stdin-stat'
object 1: size: 144
object 1: data: b'\x03\x08\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\xe8\x03\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\xb6\xea_\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\xb6\xea_\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\xb6\xea_\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
object 1: hex : 0x0308000000000000ff000000000000000100000000000000a4810000e8030000e803000000000000000000000000000000000000000000000010000000000000000000000000000013b6ea5f0000000000000000000000000eb6ea5f0000000000000000000000000eb6ea5f000000000000000000000000000000000000000000000000000000000000000000000000
object 1: text: ..........................................................................._..............._..............._....................................
object 2: name: 'model_version'
object 2: size: 4
object 2: data: b'\x01\x00\x00\x00'
object 2: hex : 0x01000000
object 2: int : 1
object 2: uint: 1
object 2: text: ....
```

Note that since we got the bitcode by lifting the binary instead of compiling
from source, in some scenarios we may not be able to change the source code to
signal the solution (or a desired state) being found, as [the original maze
example](https://feliam.wordpress.com/2010/10/07/the-symbolic-maze/) did.
However, it is still possible to link external LLVM bitcode files together
through `llvm-link` or KLEE option `--link-llvm-lib` to instrument the target
code and get the desired information or manipulate KLEE's symbolic exploration.
