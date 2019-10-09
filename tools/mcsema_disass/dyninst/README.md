# mcsema-dyninst-disass

mcsema-dyninst-disass is an experimental frontend for McSema based on the [Dyninst API](https://github.com/dyninst/dyninst). We hereby aim to provide a free frontend for McSema, whose main development branch currently requires the proprietary [IDA Pro](https://www.hex-rays.com/products/ida) software. We hope to make McSema more accessible this way to users that do not have access to an IDA Pro license.

The Dyninst frontend had been developed as part of a laboratory course at the [University of Erlangen-Nuremberg](https://www4.cs.fau.de/).
Later this code was picked up and reworked to what you currently see. You can read more about it (and a lot of other McSema related topics) in [diploma thesis](https://is.muni.cz/th/pxe1j/thesis.pdf) that was written about the frontend!

## Dependencies

You won't need IDA Pro to run mcsema-dyninst-disass, but Git, CMake, Google Protobuf and Python are still required (see the top-level McSema README.md file for details). In addition to those requirements, you will need to build and install DyninstAPI. It is available in source code form [on GitHub](https://github.com/dyninst/dyninst). Follow the instructions there on how to build and install DyninstAPI before proceeding to the next step. Use version from the branch 9.3.2.

## Building mcsema-dyninst-disass

The build process can be split into two separate phases: Dyninst API itself and McSema with this frontend. Frontend itself is not depended on McSema (it is not linked with McSema or Remill) but they do share some dependencies.

### Building Dyninst

Firstly you will need to build [Dyninst API](https://github.com/dyninst/dyninst). You will need version `9.3.2` which should be present in Dyninst `master` branch under tag `v9.3.2`. You can easily switch to the tag by:

```
git checkout v9.3.2
```

After checking out the correct version of the DynInst source code, we recommend following DynInst's build instructions, which can be found in its repository.

If you are using a newer distributions (e.g. archlinux), then you may encounter some errors during the build process. They should correspond to issues that are resolved in newer versions:

 * https://github.com/dyninst/dyninst/issues/486
 * https://github.com/dyninst/dyninst/issues/526

### Building mcsema frontend

Assuming that you've installed Dyninst to ```/usr/local/```, you need to export the following environment variables:

```shell
export CMAKE_PREFIX_PATH=/usr/local/lib/cmake/Dyninst
```

The ```CMAKE_PREFIX_PATH``` environment variable tells CMake where to find the necessary Dyninst files.

Now, you should be able to build this frontend along with McSema using the ```build.sh --dyninst-frontend``` (sets ```BUILD_MCSEMA_DYNINST_DISASS``` variable in cmake) script from the remill repository. Please see the top-level McSema README.md file for details on how to use the build script.
Compiler with C++14 support is required.

## Using mcsema-dyninst-disass

`mcsema-dyninst-disass` replaces the IDA Pro frontend in the sense that both take a binary file as input and produce a Google Protocol Buffer file as output. The output can then be fed into mcsema-lift for further processing. Command line arguments are the same as for other frontends.

In case you encounter any errors or problems during build or lift process you simply cannot get your head around, feel free to visit `#binary-lifting` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/). Also feel free to drop-by in case you want to discuss why the frontend cannot lift your binary, maybe it can be fixed quite easily!


## Known limitations
Please keep in mind the following list of limitations; we welcome pull requests for fixing bugs or implementing missing features!
* Tested *only* 64-bit ELF files, but there should not be fundamental problem with 32-bit. Support of other binary formats is possible as long as Dyninst is able to parse them. In such case a few classes would need different implementation based on chosen format specific information (jump table heuristics, recognition of xrefs in sections).
* Has *only* been tested on Linux
* Shared library are not lifted correctly
* Exceptions are ignored - it just needs to be implement, PR is welcomed.
* Binaries with debug info provides info about local variables, which is retrieved. What needs to be done is get all references to these locals. This is not provided by Dyninst and needs to be computed.
* Still needs lots of testing, debugging, corner-case handling, any feedback in form of issues or PRs is welcomed!
