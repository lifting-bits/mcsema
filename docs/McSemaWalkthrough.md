# McSema Walkthrough

In this guide we'll show how to translate a Linux binary into LLVM bitcode, and then rebuild the resulting bitcode into a new, functional binary.

The binary we'll be translating is `xz`, a [compression and decompression suite that uses LZMA](https://en.wikipedia.org/wiki/XZ_Utils). The utility is common on Linux systems, and we'll be using the version of /bin/xz that ships with Ubuntu 16.04 amd64.

Here is the exact version and hash of our test binary:

```shell
$ xz -V
xz (XZ Utils) 5.2.2
liblzma 5.2.2

$ sha256sum `which xz`
047e0a03fc04722dfa273bfc99895da4049609dd3468ec4c2e1d1c78509d71ef  /usr/bin/xz

$ file `which xz`
/usr/bin/xz: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e39115ef0c15f513cab77537cb13c9beaec0fdc1, stripped
```

This binary was chosen since it has complex features, it was easy to verify that the core functionality works.

## Assumptions

This guide assumes that you are working on a Linux system, have already built and installed a working version of McSema, and that `mcsema-lift-9.0` (for LLVM 9) and `mcsema-disass-3.8` (for Python 3.8) are in your execution path.

The guide also assumes that you have working version of IDA Pro 7.1+ that has been installed to use the system Python 3.8 interpreter. A 64-bit IDA Pro 7.x is required for control flow recovery.  Note that IDA Pro will not function until it has been launched once in standalone mode and the EULA pop-up has been accepted.

The rest of this walkthrough assumes that you have set an environment variable, `IDA_PATH` to point to your IDA installation directory. For example, on macOS, this might be something like:

```bash
export IDA_PATH=/Users/<username here>/Applications/IDA\ Pro\ 7.5/idabin
```

The directory that you put into your `IDA_PATH` should contain executables named `idat` (for disassembling 32-bit binaries) and `idat64` (for disassembling 64-bit binaries).

## Control Flow Recovery

The first step in translation is to identify all the instructions, functions, and data in the binary. This is done via `mcsema-disass-3.8`, which will use the IDA Pro disassembler to do most of the initial analysis. As of this writing IDA Pro is required for the control flow recovery step, but we hope to transition to other tools in the future.

First, let's place a copy of the binary into `/tmp`, which we'll use as our working directory:

```shell
cp /usr/bin/xz /tmp
```

Next, we'll use `mcsema-disass-3.8`, the CFG recovery portion of mcsema, to recover `xz`'s control flow.

```shell
mcsema-disass-3.8 \
    --disassembler "${IDA_PATH}/idat64" \
    --arch amd64 \
    --os linux \
    --entrypoint main \
    --pie-mode \
    --rebase 535822336 \
    --binary /tmp/xz \
    --output /tmp/xz.cfg \
    --log_file /tmp/log
```

The following explains each command-line flag:

* `--disassembler "${IDA_PATH}/idat64"`: This is a path to the IDA Pro executable which will do the bulk of the disassembly work. We're using `idat64` because `xz` is a 64-bit bit binary. If it was a 32-bit binary, we'd use `idat`.
* `--os linux`: The binary we are lifting is for the Linux operating system. It is possible to use McSema on any supported platform for any supported binary (e.g. Windows binaries can be lifted on Linux and vice versa).
* `--arch amd64`: The binary we are lifting is a 64-bit binary that uses the amd64 or x86-64 instruction set.
* `--output /tmp/xz.cfg`: Store the recovered control flow information in the file named `xz.cfg`.
* `--log_file /tmp/log`: Store a human-readable log of what was discovered into `/tmp/log`. Sometimes errors or warnings are reported in here.
* `--binary /tmp/xz`: Use `/tmp/xz` as the input binary.
* `--entrypoint main`: Specifies where the disassembler should start recovering control flow. This tells it to use the `main` function as the starting point for CFG recovery.
* `--pie-mode`: The file is an "LSB shared object", which means that it is a position-independent executable. Most binaries on modern operating systems (Ubuntu 18.04+, macOS, Windows) are position independent. This flag changes how the disassembler interprets numbers that may look like addresses.
* `--rebase 535822336`: This tells IDA to re-position the binary and pretend to load it at the address `535822336` (`0x1ff00000` in hex). This is useful for PIE binaries, otherwise IDA might load them at the zero address, and then our heuristics would have to try to interpret whether or not small numbers are actually addresses or just small numbers. We'll take advantage of this number later when re-linking the binary.

## Translation to Bitcode

Once we have the program's control flow information, we can translate it to LLVM bitcode using `mcsema-lift-9.0`. The `9.0` here is the version of the LLVM toolchain being used. McSema can be built to use LLVM version 3.6 and up. The officially supported versions are LLVM 9+.

Here is the command to translate the CFG into bitcode:

```shell
mcsema-lift-9.0 \
    --arch amd64 \
    --os linux \
    --cfg /tmp/xz.cfg \
    --output /tmp/xz.bc \
    --explicit_args \
    --merge_segments \
    --name_lifted_sections
```

The following explains each command-line flag:

* `--os linux`: Tell the lifter the OS of the binary represented by the CFG. This should match what was passed to `mcsema-disass-3.8`.
* `--arch amd64`: Tell the lifter the architecture of the binary represented by the CFG. This should match what was passed to `mcsema-disass-3.8`.
* `--cfg /tmp/xz.cfg`: The input control flow graph to convert into bitcode.
* `--output /tmp/xz.bc`: Where to write the bitcode. If the `--output` option is not specified, the bitcode will be written to `stdout`.
* `--explicit_args`: This is a bit tricky to explain. Basically, if an external function is called, then we are asking McSema to try to call it as if it were calling any old LLVM function. This means that a call in the binary to an external function shows up as a call to an LLVM function, with explicitly represented arguments passed to that function (hence the name). The lifting of explicit argument calls isn't always accurate, however. The accuracy depends entirely on IDA Pro's ability to infer or know prototype of a function, the presence/absence of floating point arguments, and the presence/absence of variadic arguments. If you are using the bitcode with KLEE then you definitely want this option; the alternative is for all externals to be called through assembly stubs without any "high level" arguments being passed. Behind the scenes, the assembly stub translates McSema's emulated registers into native machine registers, and swaps stacks. This is only supported on 64-bit Linux.
* `--merge_segments`: McSema lifts each "segment" (area containing code, data, etc.) as a global variable in LLVM. Sometimes, two or more segments are adjacent or nearby in the binary. Some addresses may point to the beginning of a segment, but be validly interpreted as one past the end of the prior (adjacent) segment. Other addresses may be formed dynamically by combining a high portion of an address (pointing into one segment) and the low portion of an address (a displacement that moves the address into the next segment). To best handle all these corner cases, we use this option to merge all these global variables into one single massive global varible. It's a bit crazy but it's more reliable.
* `--name_lifted_sections`: This tells McSema to assign each lifted segment variable to its own section. In our case, because we merged all segments into one global variable, and because we specified `--rebase 535822336` (`0x1ff00000`) at disassembly time, there will be a single section named `.section_1ff00000`. Right now this seems like an unusual thing to do; however, our goal is to recompile this bitcode to machine code. We admit that the disassembly process may miss things. Sometimes it might see a number and interpret it as an address or vice versa. To counteract these kinds of issues, we're going to position the lifted segments so that they would end up where they were rebased to in the binary. This will ensure that any numbers or addresses that may have been misinterpreted have the same bit/integer representation! Again, this is an option to improve reliability. For something like KLEE, this won't help you.

The `mcsema-lift-9.0` program may print out errors or warnings to `stderr`. Oftentimes these are not critical. The full lift log can be found in `/tmp/mcsema-lift-9.0.INFO`, and this is a link to a process/thread-ID-specific file. Make sure to clean out these log files if you use `mcsema-lift-9.0` a lot!

And there will be a generated bitcode file in the output location that we specified.

```shell
% file /tmp/xz.bc 
/tmp/xz.bc: LLVM IR bitcode
```

## Building a New Binary

The new bitcode can be used for a variety of purposes ranging from informational analyses to hardening and transformation. Eventually, though, you may want to re-create a new, working binary. Here is how to do that.

First, we need to find out the dependent libraries of `xz`. We'll need to link against each of these, as well as linking against `libm`.

```
% ldd `which xz`
  linux-vdso.so.1 (0x00007ffc8b5c4000)
  liblzma.so.5 => /lib/x86_64-linux-gnu/liblzma.so.5 (0x00007f5c72ece000)
  libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f5c72caf000)
  libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5c728be000)
  libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f5c726ba000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f5c7330b000)
```

Before installing McSema, you likely had to install Remill. As a result, you should have `remill-clang-9.0` installed as an available binary. If you don't have this then be sure to use `clang-9`, as it should be compatible with the LLVM 9 bitcode produced by `mcsema-lift-9.0`.

```bash
remill-clang-9.0 -o /tmp/xz.lifted /tmp/xz.bc -lpthread -lm -ldl -llzma -Wl,--section-start=.section_1ff00000=0x1ff00000
```

This is a fairly ordinary clang command line; the only thing of note is `-Wl,--section-start=.section_1ff00000=0x1ff00000`, which tells the linker to position the lifted segment variable, located in the section `.section_1ff00000` at the address `0x1ff00000`.

We can verify that our new binary, /tmp/xz.lifted`, works, and compresses output that can be read by `unxz`:

```shell
% /tmp/xz.lifted -V
xz (XZ Utils) 5.2.2
liblzma 5.2.2
```

Command line arguments to `xz.new` also work:

```shell
% /tmp/xz.lifted --help
Usage: /tmp/xz.lifted [OPTION]... [FILE]...
Compress or decompress FILEs in the .xz format.

  -z, --compress      force compression
  -d, --decompress    force decompression
  -t, --test          test compressed file integrity
  -l, --list          list information about .xz files
  -k, --keep          keep (don't delete) input files
  -f, --force         force overwrite of output file and (de)compress links
  -c, --stdout        write to standard output and don't delete input files
  -0 ... -9           compression preset; default is 6; take compressor *and*
                      decompressor memory usage into account before using 7-9!
  -e, --extreme       try to improve compression ratio by using more CPU time;
                      does not affect decompressor memory requirements
  -T, --threads=NUM   use at most NUM threads; the default is 1; set to 0
                      to use as many threads as there are processor cores
  -q, --quiet         suppress warnings; specify twice to suppress errors too
  -v, --verbose       be verbose; specify twice for even more verbose
  -h, --help          display this short help and exit
  -H, --long-help     display the long help (lists also the advanced options)
  -V, --version       display the version number and exit

With no FILE, or when FILE is -, read standard input.

Report bugs to <lasse.collin@tukaani.org> (in English or Finnish).
XZ Utils home page: <http://tukaani.org/xz/>
```

That's it for the walkthrough. Please let us know if any of the steps fail or change so that we can update this document. Happy translating!
