# mcsema-dyninst-disass

mcsema-dyninst-disass is an experimental frontend for McSema based on the [Dyninst API](http://www.dyninst.org/dyninst). Specifically, we make use of one of its subprojects, [ParseAPI](http://www.dyninst.org/parse), for binary file parsing and control flow recovery. We hereby aim to provide a free frontend for McSema, whose main development branch currently requires the proprietary [IDA Pro](https://www.hex-rays.com/products/ida) software. We hope to make McSema more accessible this way to users that do not have access to an IDA Pro license.

The Dyninst frontend has been developed as part of a laboratory course at the [University of Erlangen-Nuremberg](https://www4.cs.fau.de/). It is, of course, not nearly as refined (yet?) as the IDA Pro frontend, but we have been able to successfully recompile a variety of smaller applications with it.
Later this code was picked up and reworked to what you currently see. As of now it can lift most of the McSema test suite (possibly all not tested yet) including some more complicated binaries like stripped gzip. Support for position independent code is on the way, simple program are already lifted correctly.

## Dependencies

You won't need IDA Pro to run mcsema-dyninst-disass, but Git, CMake, Google Protobuf and Python are still required (see the top-level McSema README.md file for details). In addition to those requirements, you will need to build and install DyninstAPI. It is available in source code form [on GitHub](https://github.com/dyninst/dyninst). Follow the instructions there on how to build and install DyninstAPI before proceeding to the next step.

## Building mcsema-dyninst-disass

Assuming that you've installed Dyninst to ```/usr/local/```, you need to export the following environment variables:

```shell
$ export CMAKE_PREFIX_PATH=/usr/local/lib/cmake/Dyninst
$ export BUILD_MCSEMA_DYNINST_DISASS=1
```

The ```CMAKE_PREFIX_PATH``` environment variable tells CMake where to find the necessary Dyninst files, and the ```BUILD_MCSEMA_DYNINST_DISASS``` environment variable will cause the top-level CMakeLists.txt file to descend into the subdirectory where this frontend resides (otherwise it won't get built).

Now, you should be able to build this frontend along with McSema using the ```build.sh``` script from the remill repository. Please see the top-level McSema README.md file for details.

## Running the tests

mcsema-dyninst-disass comes with a few test cases. To try them out, make sure you have built both this frontend as well as mcsema-lift. Then, chdir to ```mcsema/tools/mcsema_disass/dyninst/tests``` (in the source code tree), where you will find a Python script ```run_tests.py```.

```shell
$ ./run_tests.py -h
```

provides an overview of the required command line options. Supplied with the proper arguments, the script will then proceed to build, disassemble, lift and recompile the test programs in a temporary directory, each time running both the original as well as the recompiled binary and then passing the test iff the outputs match. Python 2.7 won't work, implemented with Python 3.5 in mind.

## Using mcsema-dyninst-disass

mcsema-dyninst-disass replaces the IDA Pro frontend in the sense that both take a binary file as input and produce a Google Protocol Buffer file as output. The output can then be fed into mcsema-lift for further processing.

## Known limitations
Pull request fixing bugs or implementing missing features are welcomed!
* Tested *only* 64-bit ELF files, but there should not be fundamental problem with 32-bit
* Has *only* been tested on Linux
* Exceptions are ignored ( work in progress )
* Still needs lots of debugging, corner-case handling, ...

## How does it work
* First thing is getting address of main and init/fini in case that binary is stripped.
* External function are retrieved based on information provided by DyninstAPI
    * This may not cover every external function. In case that there is later a symbol in relocations we have no information about, we first check std-defs provided by user. This is unpleasant, since it would nice to get rid of it.
    * For each function relocations are computed with ea out of binary
* External variables are written with relocation out of binary only if Dyninst have no information about them except for name (ea and size are both 0)
* Next are section.
    * Some information about variables in them may be provided by symtab
    * Global offset family is written including relocations got from externals, so output is the same as IDA fronend
    * .data and .rodata use following technique to search for xrefs and variables:
        * Read from first no-zero to zero. If it is small enough try to check if it is pointer at something we already know about. If no add it to be resolved later. If it's big, we say it's variable.
    * Other region are for now just read by 8bytes and checked for xrefs, ignoring possible variables.
* After all section are written xrefs that were put aside are resolved. If they don't point to anything they are probably variable.
* Exceptions are references into .text section which may point some function we don't have due to binary being stripped. Therefore we try mark target of those xrefs as function entries.
* Global variables are fully dependent on info from Dyninst
* Internal function are written last
    * References matched against external functions/vars, here Dyninst gets address of thunk so there is need to recalculate it to relocation
    * Other possible targets are other xrefs from segments, global variables and other functions.
    * If none is matched we assume we just missed some and say it is xref anyway. This seems to work, but is not the best solution.
* After functions are parsed and written there could be some xrefs pointing into .text unresolved, so they are probably other functions we missed. We continue to parse until fixpoint over set of these xrefs is calculated.
