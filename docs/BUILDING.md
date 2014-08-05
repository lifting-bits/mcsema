# Building on Windows

This section describes how to build mcsema on Windows using Visual Studio 2010 or Visual Studio Express 2013.

The specific platforms used for these examples were Windows 7 32-bit (for Visual Studio 10) and WIndows 8.1 64-bit for Visual Studio Express 13.

The semantics testing can **only be built on Visual Studio 2010** due to a dependency on a specific version of Intel PIN. The rest of mcsema will build using other versions of Visual Studio. 

## Prerequisites
General Packages:
* CMake (version 2.8.12.2 is required for VS2013 support).
* mcsema source
* git
* Python 2.7

Build Environment:

* Visual Studio 2010
* Visual Studio 2010 SP1 (http://www.microsoft.com/en-us/download/details.aspx?id=23691)
* Intel Pin 2.10 (Revision 45467) for VS2010 (http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.10-45467-msvc10-ia32_intel64-windows.zip, needed for semantics testing only)

or:
* Visual Studio Express 2013 For Windows Desktop (http://www.microsoft.com/en-us/download/details.aspx?id=40787)

**Other versions of Visual Studio will probably work via the VS Express 2013 directions, but have not been tested.**


## Install Prerequisites

### Visual Studio 2010

If using Visual Studio 2010, SP1 is **ABSOLUTELY REQUIRED**. The build will fail without it.

VS 2010 builds support semantics testing. You need Intel PIN to run the tests. Intel Pin should be extracted to `mc-sema\thirdparty\win32\pin`. See the documentation in `mc-sema\thirdparty\win32` for more details.

### Visual Studio 2013

If using Visual Studio Express 2013 the Desktop Edition is **ABSOLUTELY REQUIRED**. The build will fail without it.

Do **not** install Intel PIN. It wont link correctly. Semantics tests will not be available, but everything else will work.

## Get The Source

Clone the source from Git. If you are reading this, odds are you know where the git repository is located.  For the rest of these examples, please check out the source into the `llvm-lift` directory.

## Building

The following examples assume the source has already been cloned from git into a directory called `llvm-lift`.


### Visual Studio 2010

Open a Visual Studio 2010 Command Prompt ( Start->Microsoft Visual Studio 2010->Visual Studio Tools->Visual Studio Command Prompt (2010) ).

* `cd C:\git\llvm-lift` (or wherever you checked out the source).
* `mkdir build`
* `cd build`

#### Debug Builds

If doing a Debug build (if you are doing active development, you probably want this) run the following commands:

* `cmake -G "Visual Studio 10" -DCMAKE_BUILD_TYPE=Debug ..`
* `devenv mc-sema.sln /build Debug /project ALL_BUILD`

The resulting binaries and debugging symbols (.PDB files) should now be in `build\bin\Debug`.

#### Release Builds

If you are doing a Release build (that is, using the code in a production environment) run the following commands:

* `cmake -G "Visual Studio 10" -DCMAKE_BUILD_TYPE=Release ..`
* `devenv mc-sema.sln /build Release /project ALL_BUILD`

There might not be any PDB files with release builds.

Note: On multiprocessor machines `devenv` will build the source in parallel. This will result in some failed builds since some projects are built before their pre-requisites exist. Re-run the full `devenv` command again and it should build without issues the second time.

### Visual Studio Express 2013

Open a Visual Studio 2013 x86 Native Tools Command Prompt ( `C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\Shortcuts\VS2013 x86 Native Tools Command Prompt` ).

* `cd C:\git\llvm-lift` (or wherever you checked out the source).
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

    C:\git\llvm-lift\mc-sema\tests>demo1.bat
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
