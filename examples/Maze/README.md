# Solving a Maze with KLEE and McSema

This walkthrough describes how to run KLEE on a simple Maze program. The instructions here have been tested on Ubuntu 16.04. Your mileage may vary if you are using another operating system. What is unique about this walkthrough is that it will show that KLEE runs equally well on lifted bitcode produced from the same program compiled to x86-64 (amd64) and AArch64 (64-bit ARMv8).

The program, [Maze.c](Maze.c), can be found in this directory, along with the [binaries](bin) and [control-flow graph files](cfg) for the Maze program.

## The Maze

The Maze program presents its user with the following challenge: type in a sequence of `w`, `s`, `a`, or `d` characters to guide the `X` through the maze and reach the destination denoted by `#`.

The characters `w`, `s`, `a`, and `d` are used in place of the keyboard's arrow keys, that is:

```
    +---+               +---+    
    | w |               | ^ |    
+---+---+---+  <=>  +---+---+---+
| a | s | d |       | < | v | > |
+---+---+---+       +---+---+---+
```

Initially, the program displays the maze, and asks the user to type in their directions for how to complete it.

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

The winning directions for the maze are `ssssddddwwaawwddddssssddwwww`. The winning output looks like this:

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

### Step 1: Get dependencies

The first step is to make sure that we have all the dependencies that we need.

```bash
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     cmake \
     python2.7 python-pip \
     wget \
     build-essential \
     gcc-multilib g++-multilib \
     libtinfo-dev \
     lsb-release \
     realpath \
     z3 libz3-dev \
     libncurses5-dev

sudo pip install --upgrade pip
sudo pip install 'protobuf==3.2.0'
```

Now that we have the dependencies we need, we should clone [Remill](https://github.com/lifting-bits/remill).

```bash
cd ~/data
git clone https://github.com/lifting-bits/remill.git
```

### Step 2: Build Remill, McSema, and KLEE

We have provided a convenient [script](https://github.com/lifting-bits/remill/blob/master/scripts/build_klee.sh) for this walkthrough. The script will clone the latest version of McSema into the Remill checkout, as well as clone a version of KLEE that is compatible with Remill. You might already have McSema installed, and it might be a version that is not compatible with KLEE. That is not a problem. The script will ensure that the proper toolchain is built *within* the directory in which you invoke the script.

```bash
mkdir /tmp/klee_ws
cd /tmp/klee_ws
```

Now to invoke our build script within `/tmp/klee_ws`, which is where Remill, McSema, and KLEE will be compiled.

```bash
~/data/remill/scripts/build_klee.sh
```

### Step 3: Lift the Maze binaries

From within the KLEE workspace `/tmp/klee_ws`, run the [lifting script](scripts/lift.sh). This script invokes `mcsema-lift-3.9` on the provided [CFG files](cfg). If you have IDA Pro, then you can reproduce these steps manually by invoking the [disassembly script](scripts/disass.sh).

```bash
~/data/remill/tools/mcsema/examples/Maze/scripts/lift.sh
```

This script will likely print out some error messages. That is okay. McSema will always try to produce bitcode, and it will warn you when something seems erroneous in the CFG file.

### Step 4: Run KLEE

The build script from step 2 will have compiled KLEE into the `/tmp/klee_ws/klee-build/` directory. We can run the KLEE using the following commands. If things work, then there will be a lot of funny looking output.

```bash
./klee-build/bin/klee -posix-runtime -libc=uclibc -allow-external-sym-calls ~/data/remill/tools/mcsema/examples/Maze/bc/maze.amd64.bc -sym-stdin 28
```

```bash
./klee-build/bin/klee -posix-runtime -libc=uclibc -allow-external-sym-calls ~/data/remill/tools/mcsema/examples/Maze/bc/maze.aarch64.bc -sym-stdin 28
```

### Step 5: Example ouput

We know that the answer to the maze is `ssssddddwwaawwddddssssddwwww`, so we can check to see if KLEE found it by running `ktest-tool` on all of the `.ktest`-suffixed files in the KLEE's output file directory (`klee-last` is a symlink to the most recently produced output directory).

```bash
for f in ~/data/remill/tools/mcsema/examples/Maze/bc/klee-last/*.ktest ; do
  ./klee-build/bin/ktest-tool $f | grep ssssddddwwaawwddddssssddwwww &>/dev/null ;
  if [[ $? -eq 0 ]] ; then
    FOUND_TEST=$f
  fi
done
./klee-build/bin/ktest-tool $FOUND_TEST
```

The output we get should be something like the following:

```
ktest file : '~/data/remill/tools/mcsema/examples/Maze/bc/klee-last/test000301.ktest'
args       : ['~/data/remill/tools/mcsema/examples/Maze/bc/maze.aarch64.bc', '-sym-stdin', '28']
num objects: 3
object    0: name: 'stdin'
object    0: size: 28
object    0: data: 'ssssddddwwaawwddddssssddwwww'
object    1: name: 'stdin-stat'
object    1: size: 144
object    1: data: '\x02\x08\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\xe8\x03\x00\x00\xe8\x03\x00\x00\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x00\x10\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01R\x06XZ\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\xbb\x1dXZ\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\xbb\x1dXZ\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01'
object    2: name: 'model_version'
object    2: size: 4
object    2: data: '\x01\x00\x00\x00'
```