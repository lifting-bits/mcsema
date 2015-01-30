# Building on Linux

This section describes how to build mcsema on Linux. The build was tested on Ubuntu 14.04.

The test examples (`mc-sema/tests/*.sh`) use clang to build the object files by default. This can be changed to gcc by editing `mc-sema/tests/env.sh`. Both compilers should work.

## Prerequisites

Required:
* Python 2.7
* CMake
* git
* nasm
* mcsema source
* development tools (e.g. the `build-essential` package)
* 32-bit development libraries (`libc6:i386`, `gcc-multilib`)

Recommended:
* clang

## Get The Source

Clone the source from Git. If you are reading this, odds are you know where the git repository is located.  For the rest of these examples, please check out the source into the `mcsema` directory.

## Building

Ubuntu 14.04 - i386
* sudo apt-get install git gcc-multilib g++-multilib build-essential cmake nasm

Ubuntu 14.04 - x86_64

* sudo apt-get install git gcc-multilib g++-multilib build-essential cmake libc6-i386 nasm

The following examples assume the source has already been cloned from git into a directory called `mcsema`.

* `git clone https://github.com/trailofbits/mcsema`
* `cd mcsema` (or wherever you checked out the source)
* `mkdir build`
* `cd build`

### Debug Builds

If doing a Debug build (if you are doing active development, you probably want this) run the following commands:

* `cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug ..`
* `make`

The resulting binaries and debugging symbols (.PDB files) should now be in `build\bin\Debug`.

### Release Builds

If you are doing a Release build (that is, using the code in a production environment) run the following commands:

* `cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release ..`
* `make`

## Testing the Build

There should not be any build errors in the build output.

To verify functionality, try running the demos (in `mc-sema/tests`). For example:

    $ ./demo1.sh
    Using bin_descend to recover CFG
    Looking at Object File section: .text
    Found symbol: .text in .text
    Found symbol: filler in .text
    Found symbol: start in .text
    addDataEntryPoints: skipping non-data section: .text
    Calling getFunc on: 1
    getFunc: Starting at 0x1
    getFunc: toVisit size is: 1
    Processing block: block_0x1
    1:      addl    $1, %eax
    4:      ret
    getFunc: Function recovery complete for  func at 1
    Already have driver for: start
    Inserted function: sub_1
    Adding entry point: demo1_entry
    0xC -> 0xD

# Building on Windows

mcsema now requires C++11 due to integration with LLVM 3.5. Please build with Visual Studio 2012 or later.

## Prerequisites
General Packages:
* CMake (version 2.8.12.2 is required for VS2013 support).
* mcsema source
* git
* Python 2.7

Build Environment:

* Visual Studio 2012 or later

## Install Prerequisites

### Visual Studio 2013

If using Visual Studio Express 2013 the Desktop Edition is **ABSOLUTELY REQUIRED**. The build will fail without it.

Do **not** install Intel PIN. It won't link correctly. Semantics tests will not be available, but everything else will work.

## Get The Source

Clone the source from Git. If you are reading this, odds are you know where the git repository is located.  

## Building

The following examples assume the source has already been cloned from git into a directory called `mcsema`.

### Visual Studio Express 2013

Open a Visual Studio 2013 x86 Native Tools Command Prompt ( `C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\Shortcuts\VS2013 x86 Native Tools Command Prompt` ).

* `cd C:\git\mcsema` (or wherever you checked out the source).
* `mkdir build`
* `cd build`

#### Debug Builds

If doing a Debug build (if you are doing active development, you probably want this) run the following commands:

* `cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug ..`
* `nmake`

The resulting binaries and debugging symbols (.PDB files) should now be in per-project directories under `build`.

#### Release Builds

If you are doing a Release build (that is, using the code in a production environment) run the following commands:

* `cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release ..`
* `nmake`

There might not be any PDB files with release builds.

### Other Versions

There are two main options for other Visual Studio versions: 

* Follow the VS 2013 directions with the "NMake Files" target. Try this first.
* Adjust the `-G` in the cmake command line to generate the correct build files for your Visual Studio version. For a list of generators, see `cmake --help`. Figure out how to build the resulting solution file.

## Testing the Build

There should not be any build errors in the build output.

To verify functionality, try running the demos. For example:

    C:\git\mcsema\mc-sema\tests>demo1.bat
    Using bin_descend to recover CFG
    getFunc: Starting at 0x1
    Processing block: block_0x1
    1:      addl    $1, %eax
    4:      ret
    getFunc: Function recovery complete for  func at 1
    Already have driver for: start
    Adding entry point: demo1_entry
    demo_driver1.c
    LINK : demo_driver1.exe not found or not built by the last incremental link; performing full link
    0xC -> 0xD
