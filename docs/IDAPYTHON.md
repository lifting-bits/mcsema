# IDAPython Preparation Guide

Prior to using IDAPython for control flow graph recovery, the IDAPython installation needs to know about Google protocol buffer libraries.

The below guide is for Windows installations. The Mac and Linux procedure should be similar in spirit: find IDA's Python installation and use it to install protobuf libraries.

# Intallation Steps (Windows)

The following instructions were tested on Windows 7 x86 using Python 2.7 and IDA 6.5.

* Install Python 2.7. For example purposes, it is assumed it will be installed to `C:\Python27`.

* Install IDA. By default IDA will use your existing Python 2.7 installation.

* Download the binary Google Protocol Buffers distribution for Windows. This should be called `protoc-2.5.0-win32.zip`. It can be downloaded from the protobuf Google Code repository:
 https://protobuf.googlecode.com/files/protoc-2.5.0-win32.zip.

* Extract the protocol buffers distribution to `C:\protoc-2.5.0-win32`.

* Get the Google Protocol Buffers source code. This is also avialble from the protobuf Google Code repository: https://protobuf.googlecode.com/files/protobuf-2.5.0.zip.

* Extract the protobuf source anywhere convenient.

* Open a command prompt and natigate to the directory with the source code.

* Copy the binary protocol buffers compiler into the Python portion of the source tree:

  `cd python`

  `copy "C:\protoc-2.5.0-win32\protoc.exe" ..\src`

* Build protobufs:

  `C:\Python27\python.exe setup.py build`

* Install protobufs:

  `C:\Python27\python.exe setup.py install`
