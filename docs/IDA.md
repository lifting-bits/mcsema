IDA Pro Setup for McSema
========================

# Linux Instructions
These instructions describe the prerequisites for using IDA Pro for CFG Recovery under Linux.

## Install IDA Pro

When given the option, select to use bundled Python. Using the system Python may work, as long as the IDAPython plugin still runs and `python-protobuf` will install.

## Install helper libraries

IDA does not install some of the libraries it needs to run. Lets help it out, and also install Google protocol buffer support for Python.

     sudo dpkg --add-architecture x86
     sudo apt-get update
     sudo apt-get install libncurses5:i386 zlib1g:i386
     sudo ln -s /lib/i386-linux-gnu/libncurses.so.5 /lib/i386-linux-gnu/libcurses.so
     sudo apt-get install python-protobuf
     sudo updatedb

## Accept the License Agreement

Run IDA as the user you will be using for McSema work and accept the license agreement
