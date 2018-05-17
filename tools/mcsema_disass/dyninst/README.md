# mcsema-dyninst-disass

mcsema-dyninst-disass is an experimental frontend for McSema based on the [Dyninst API](http://www.dyninst.org/dyninst). Specifically, we make use of one of its subprojects, [ParseAPI](http://www.dyninst.org/parse), for binary file parsing and control flow recovery. We hereby aim to provide a free frontend for McSema, whose main development branch currently requires the proprietary [IDA Pro](https://www.hex-rays.com/products/ida) software. We hope to make McSema more accessible this way to users that do not have access to an IDA Pro license.

The Dyninst frontend has been developed as part of a laboratory course at the [University of Erlangen-Nuremberg](https://www4.cs.fau.de/). It is, of course, not nearly as refined (yet?) as the IDA Pro frontend, but we have been able to successfully recompile a variety of smaller applications with it. Feel free to have a look at the ```tests/``` subdirectory to get a quick overview of what's already possible.

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

provides an overview of the required command line options. Supplied with the proper arguments, the script will then proceed to build, disassemble, lift and recompile the test programs in a temporary directory, each time running both the original as well as the recompiled binary and then passing the test iff the outputs match.

## Using mcsema-dyninst-disass

mcsema-dyninst-disass replaces the IDA Pro frontend in the sense that both take a binary file as input and produce a Google Protocol Buffer file as output. The output can then be fed into mcsema-lift for further processing.

A typical invocation of mcsema-dyninst-disass might look like this:

```shell
$ mcsema-dyninst-disass -o out.cfg --std-defs [...]/mcsema/tools/mcsema_disass/defs/linux.txt [...]/a.out
```

mcsema-dyninst-disass can also accept additional external symbol definitions from the command line; use ```--help``` for a full list of available options.

## Known limitations
Pull request fixing bugs or implementing missing features are welcomed!
* Can *only* handle 64-bit ELF files
* Has *only* been tested on Linux
* Exceptions are ignored 
* Virtual methods ( late bind ) do now work completely
* Still needs lots of debugging, corner-case handling, ...
