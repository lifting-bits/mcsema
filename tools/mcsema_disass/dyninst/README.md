# mcsema-dyninst-disass

mcsema-dyninst-disass is an experimental frontend for McSema based on the [Dyninst API](http://www.dyninst.org/dyninst). We hereby aim to provide a free frontend for McSema, whose main development branch currently requires the proprietary [IDA Pro](https://www.hex-rays.com/products/ida) software. We hope to make McSema more accessible this way to users that do not have access to an IDA Pro license.

The Dyninst frontend had been developed as part of a laboratory course at the [University of Erlangen-Nuremberg](https://www4.cs.fau.de/).
Later this code was picked up and reworked to what you currently see. As of now it can lift most of the McSema test suite (possibly all not tested yet) including some more complicated binaries like stripped gzip. Position independent binaries work for small tests, status of bigger binaries is unknown, although there is no known reason for them not to work correctly.

## Dependencies

You won't need IDA Pro to run mcsema-dyninst-disass, but Git, CMake, Google Protobuf and Python are still required (see the top-level McSema README.md file for details). In addition to those requirements, you will need to build and install DyninstAPI. It is available in source code form [on GitHub](https://github.com/dyninst/dyninst). Follow the instructions there on how to build and install DyninstAPI before proceeding to the next step. Use version from the branch 9.3.2.

## Building mcsema-dyninst-disass

Assuming that you've installed Dyninst to ```/usr/local/```, you need to export the following environment variables:

```shell
export CMAKE_PREFIX_PATH=/usr/local/lib/cmake/Dyninst
```

The ```CMAKE_PREFIX_PATH``` environment variable tells CMake where to find the necessary Dyninst files.

Now, you should be able to build this frontend along with McSema using the ```build.sh --dyninst-frontend``` (sets ```BUILD_MCSEMA_DYNINST_DISASS``` variable in cmake) script from the remill repository. Please see the top-level McSema README.md file for details.
Compiler with C++14 support is required.

## Using mcsema-dyninst-disass

mcsema-dyninst-disass replaces the IDA Pro frontend in the sense that both take a binary file as input and produce a Google Protocol Buffer file as output. The output can then be fed into mcsema-lift for further processing. Command line arguments are the same as for other frontends.

## Known limitations
Pull request fixing bugs or implementing missing features are welcomed!
* Tested *only* 64-bit ELF files, but there should not be fundamental problem with 32-bit. Support of other binary formats is possible as long as Dyninst is able to parse them. In such case a few classes would need different implementation based on chosen format specific information (jump table heuristics, recognition of xrefs in sections).
* Has *only* been tested on Linux
* Shared library are not lifted correctly
* Exceptions are ignored - it just needs to be implement, PR is welcomed.
* Binaries with debug info provides info about local variables, which is retrieved. What needs to be done is get all references to these locals. This is not provided by Dyninst and needs to be computed.
* Still needs lots of testing, debugging, corner-case handling, any feedback in form of issues or PRs is welcomed!
