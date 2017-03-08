# Building on Linux

This sections describes building on Linu. It has been tested on Ubuntu 14.04 and 16.04

Mcsema ships with a script named `bootstrap.sh` that will install prerequsites and perform all build operations. This is the recommended method for building and installation.

## Prequisites

Required:
* Python 2.7
* git
* mcsema source
* development tools (e.g. the `build-essential` package)

## Get the source

Clone the source from Git. If you are reading this, odds are you know where the git repository is located.  For the rest of these examples, please check out the source into the `mcsema` directory.

## Build

* `git clone https://github.com/trailofbits/mcsema`
* `cd mcsema`
* `sudo ./bootstrap.sh`

## Bootstrap.sh

By default `bootstrap.sh` will produce a debug build and install it globally. To change this behavior use the command line flag `--build <BUILD TYPE>` to change the build type (e.g., `Debug` or `Release`) and `--prefix <PREFIX>` to change the installation directory prefix (e.g., `/usr/local/analysis`)
