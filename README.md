# McSema [![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

McSema (pronounced 'em see se ma'), short for machine code semantics, is a set of tools for lifting x86 and amd64 binaries to LLVM bitcode modules. McSema is able to lift integer, floating point, and SSE instructions.

McSema is separated into two conceptual parts: control flow recovery and instruction translation. Control flow recovery is performed using the `mcsema-disass` tool, which uses IDA Pro to disassemble a binary file and produces a CFG file. Instruction translation is performed using the `mcsema-lift` tool, which converts a CFG file into a lifted bitcode module.

McSema is open-source and licensed under the BSD 3-clause license.

## Build Status

|       | master |
| ----- | ------ |
| Linux | [![Build Status](https://travis-ci.org/trailofbits/mcsema.svg?branch=master)](https://travis-ci.org/trailofbits/mcsema) |

## Additional Documentation
 
 - [Navigating the source code](docs/NAVIGATION.md)
 - [Design and architecture](docs/ARCHITECTURE.md)
 - [How to implement the semantics of an instruction](docs/ADD_AN_INSTRUCTION.md)
 - [Usage and APIs](docs/USAGE_AND_APIS.md)
 - [Limitations](docs/LIMITATIONS.md)

**Note:** McSema is undergoing modernization and architectural changes, so some documentation may be out-of-date, or in the process of being improved.

## Getting Help

If you are experiencing undocumented problems with McSema, or just want to learn more and contribute, then ask for help in the `#tool-mcsema` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/). Alternatively, you can join our mailing list at [mcsema-dev@googlegroups.com](https://groups.google.com/forum/?hl=en#!forum/mcsema-dev) or email us privately at mcsema@trailofbits.com.

## Supported Platforms

McSema is supported on Windows and Linux platforms and has been tested on Windows 10, Ubuntu 14.04, and Ubuntu 16.04.

## Dependencies

| Name | Version | 
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 2.8+ |
| [Google Protobuf](https://github.com/google/protobuf) | 2.6.1 |
| [LLVM](http://llvm.org/) | 3.8 |
| [Clang](http://clang.llvm.org/) | 3.8 |
| [Python](https://www.python.org/) | 2.7 | 
| [Python Package Index](https://pypi.python.org/pypi) | Latest |
| [python-protobuf](https://pypi.python.org/pypi/protobuf) | 2.6.1 |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 6.7+ |


## Getting and Building the Code

### Step 1: Install dependencies

#### On Linux

##### Run

```shell
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     cmake \
     libprotoc-dev libprotobuf-dev libprotobuf-dev protobuf-compiler \
     python2.7 python-pip \
     llvm-3.8 clang-3.8 \
     realpath

sudo pip install --upgrade pip
sudo pip install 'protobuf==2.6.1'
```

##### Using IDA on 64 bit Ubuntu

If your IDA install does not use the system's Python, you can add the `protobuf` library manually to IDA's zip of modules.

```
# Python module dir is generally in /usr/lib or /usr/local/lib
touch /path/to/python2.7/dist-packages/google/__init__.py
cd /path/to/lib/python2.7/dist-packages/              
sudo zip -rv /path/to/ida-6.X/python/lib/python27.zip google/
sudo chown your_user:your_user /home/taxicat/ida-6.7/python/lib/python27.zip
```

#### On Windows

##### Step 1: Download Chocolatey

Download and install [Chocolatey](https://chocolatey.org/install).

##### Step 2: Install Packages

Open Windows Powershell in *administrator* mode, and run the following.

```shell
choco install -y --allowemptychecksum git cmake python2 pip wget unzip 7zip
choco install -y microsoft-visual-cpp-build-tools --installargs "/InstallSelectableItems Win81SDK_CppBuildSKUV1;Win10SDK_VisibleV1"
```

### Step 2: Clone and Enter the Repository

#### On Linux

##### Clone the repository

```shell
git clone git@github.com:trailofbits/mcsema.git --depth 1
```

##### Run the bootstrap script
```shell
cd mcsema
./bootstrap.sh --build Release
```

The Linux bootstrap script supports two configuration options:

  * `--prefix`: The installation directory prefix for mcsema-lift. Defaults to the directory containing the bootstrap script.
  * `--build`: Set the build type. Defaults to `Debug`

#### On Windows

##### Clone the repository

Open the Developer Command Prompt for Visual Studio application, and run the following 

```shell
cd C:\
if not exist git mkdir git
cd git

git clone https://github.com/trailofbits/mcsema.git --depth 1
```

##### Run the bootstrap script
```shell
cd mcsema
bootstrap
```

#### Step 3: Build and install the code

#### On Linux

```shell
cd build
make
sudo make install
```

#### On Windows

```shell

```

## Try it Out

If you have a binary, you can get started with the following commands. First, you recover control flow graph information using `mcsema-disass`. For now, this needs to use IDA Pro as the disassembler.

```shell
mcsema-disass --disassembler /path/to/ida/idal64 --arch amd64 --os linux --output /tmp/ls.cfg --binary /bin/ls --entrypoint main
```

Once you have the control flow graph information, you can lift the target binary using `mcsema-lift`.

```shell
mcsema-lift --arch amd64 --os linux --cfg /tmp/ls.cfg --entrypoint main --output /tmp/ls.bc
```

There are a few things that we can do with the lifted bitcode. The usual thing to do is to recompile it back to an executable.
```shell
clang-3.8 -o /tmp/ls_lifted generated/ELF_64_linux.S /tmp/ls.bc -lpthread -ldl -lpcre /lib/x86_64-linux-gnu/libselinux.so.1
```
