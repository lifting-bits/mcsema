# McSema Walkthrough

In this guide we'll show how to translate a Linux binary into LLVM bitcode, and then rebuild the resulting bitcode into a new, functional binary.

The binary we'll be translating is `xz`, a [compression and decompression suite that uses LZMA](https://en.wikipedia.org/wiki/XZ_Utils). The utility is common on Linux systems, and we'll be using the version of /bin/xz that ships with Ubuntu 16.04 amd64.

Here is the exact version and hash of our test binary:

```shell
$ ./xz -V
xz (XZ Utils) 5.1.0alpha
liblzma 5.1.0alpha

$ sha256sum ./xz
c3512fe134c78d7d734c6607a379b5f0d65276e8953a0a985e3e688356303223  ./xz
```

This binary was chosen since it has complex features, it was easy to verify that the core functionality works, and at the time of writing, it demonstrated some common lifting failures and how to work around them.

## Assumptions

This guide assumes that you are working on a Linux system, have already built and installed a working version of McSema, and that `mcsema-lift` and `mcsema-disass` are in your execution path. We assume that the McSema repository was cloned into `$MCSEMA_DIR`.

The guide also assumes that you have working version of IDA Pro, which is required for control flow recovery.  Note that IDA Pro will not function until it has been launched once in standalone mode and the EULA pop-up has been accepted.  If using IDA Pro 7, the legacy x86 32-bit version should be installed as the 64-bit version is not yet supported.

For clarity, we assume that all operations happen in `~/mcsema`, but any directory will work.

## Control Flow Recovery

The first step in translation is to identify all the instructions, functions, and data in the binary. This is done via `mcsema-disass`, which will use the IDA Pro disassembler to do most of the initial analysis. As of this writing IDA Pro is required for the control flow recovery step, but we hope to transition to other tools in the future.

First, let's place a copy of the binary in our working directory:

```shell
cd ~/mcsema
cp /usr/bin/xz ./
```

Next, we'll use `mcsema-disass`, the CFG recovery portion of mcsema, to recover `xz`'s control flow.

```shell
mcsema-disass --disassembler ~/ida-6.9/idal64 --os linux --arch amd64 --output xz.cfg --binary xz --entrypoint main --log_file xz.log
```

Let's walk through each option:

* `--disassembler ~/ida-6.9/idal64`: This is a path to the IDA Pro executable which will do the bulk of the disassembly work.
* `--os linux`: The binary we are lifting is for the Linux operating system. It is possible to use mcsema on any supported platform for any supported binary (e.g. Windows binaries can be lifted on Linux and vice versa).
* `--arch amd64`: The binary we are lifting is a 64-bit binary that uses the amd64 or x86_64 instruction set.
* `--output xz.cfg`: Store the recovered control flow information in the file named `xz.cfg`.
* `--binary xz`: Use `xz` as the input binary
* `--entrypoint main`: Specifies where the disassembler should start recovering control flow. This tells it to use the `main` function as the starting point for CFG recovery.
* `--log_file xz.log`: Where to store the disassembly log. This is optional, but it greatly aids in debugging, as we shall see later in this guide.

### Fixing Errors

This section documents how to fix a common CFG recovery problem: undefined external functions. By the time you are reading this guide, the functions described here may have already been added to the [list of common external Linux functions that comes with mcsema](https://github.com/trailofbits/mcsema/blob/master/tools/mcsema_disass/defs/linux.txt) and you can skip this section.

The previous command may have failed (as in this snippet). If it did, read on. If not, skip this section and move on to Translation To Bitcode.

```shell
$ mcsema-disass --disassembler ~/ida-6.9/idal64 --os linux --arch amd64 --output xz.cfg --binary xz --entrypoint main --log_file xz.log
Generated an invalid (zero-sized) CFG. Please use the --log_file option to see an error log.
```

Let's take a look at the log, like the message suggests:

```shell
$ tail xz.log
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1693, in recoverFunction
    recoverFunctionFromSet(M, F, blockset, new_eas)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1681, in recoverFunctionFromSet
    I, endBlock = instructionHandler(M, B, head, new_eas)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 817, in instructionHandler
    if doesNotReturn(fn):
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 220, in doesNotReturn
    raise Exception("Unknown external: " + fname)
Exception: Unknown external: __open_2
```

This means the binary is trying to call an external function, but mcsema does not know what calling convention it is, or how many arguments to give it. After searching for `__open_2` we can see that it's a C library function that takes two arguments. We can tell mcsema about it via a custom external definitions file.

Create a new file in your working directory named `xz_defs.txt` with the following content:

    __open_2 2 C N

This tells mcsema that the function is named `__open_2`, it takes `2` arguments, its calling convention is `C`aller cleanup, and the function returns (or is `N`ot noreturn, as mcsema sees it).

Now let's tell `mcsema-disass` about our new definitions file:

```shell
$ mcsema-disass --disassembler ~/ida-6.9/idal64 --os linux --arch amd64 --output xz.cfg --binary xz --entrypoint main --log_file xz.log --std-defs xz_defs.txt
Generated an invalid (zero-sized) CFG. Please use the --log_file option to see an error log.
```

Oh no! It's still failing? Let's check the log again:

```shell
$ tail xz.log
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1693, in recoverFunction
    recoverFunctionFromSet(M, F, blockset, new_eas)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 1681, in recoverFunctionFromSet
    I, endBlock = instructionHandler(M, B, head, new_eas)
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 817, in instructionHandler
        if doesNotReturn(fn):
  File "/home/artem/.local/lib/python2.7/site-packages/mcsema_disass-0.0.1-py2.7.egg/mcsema_disass/ida/get_cfg.py", line 220, in doesNotReturn
    raise Exception("Unknown external: " + fname)
Exception: Unknown external: __vfprintf_chk
```

The culprit is another missing external function. Let's add this one is as well. Our new `xz_defs.txt` should now look like:

    __open_2 2 C N
    __vfprintf_chk 4 C N

Finally, our command should succeed. We can verify that the CFG recovery completed by looking at the size of the generated CFG:

```shell
$ mcsema-disass --disassembler ~/ida-6.9/idal64 --os linux --arch amd64 --output xz.cfg --binary xz --entrypoint main --log_file xz.log --std-defs xz_defs.txt
$ ls -lh xz.cfg
-rw-rw-r-- 1 artem artem 212K Mar  8 14:54 xz.cfg
```

If header files are available that declare these external functions, these files can be automatically generated using the [DEF file generation script](DEFFileGeneration.md).

## Translation to Bitcode

Once we have the program's control flow information, we can translate it to LLVM bitcode using `mcsema-lift-4.0`. The `4.0` here is the version of the LLVM toolchain being used. McSema can be built to use LLVM version 3.6 and up.

Here is the command to translate the CFG into bitcode:

```shell
mcsema-lift-4.0 --os linux --arch amd64 --cfg xz.cfg --output xz.bc
```

Let's explore the options one by one:

* `--os linux`: The CFG came from a binary for the Linux operating system. Currently the valid options are `linux` or `windows`. This option is required for certain aspects of translation, like ABI compatibility for external functions, etc.
* `--arch amd64`: Use instruction semantics for the `amd64` architecture. Valid options are `x86` and `x86_avx` (32-bit x86 semantics), `amd64` and `amd64_avx` (64-bit x86), and `aarch64` (64-bit ARMv8).
* `--cfg xz.cfg`: The input control flow graph to convert into bitcode.
* `--output xz.bc`: Where to write the bitcode. If the `--output` option is not specified, the bitcode will be written to stdout.

The `mcsema-lift-4.0` program may print out errors or warnings to `stderr`. Oftentimes these are not critical. The full lift log can be found in `/tmp/mcsema-lift-4.0.INFO`, and this is a link to a process/thread-ID-specific file. Make sure to clean out these log files if you use `mcsema-lift-4.0` a lot!

And there will be a generated bitcode file in the output location we specified:

```shell
$ ls -lh xz.bc
-rw-rw-r-- 1 artem artem 1.9M Mar  8 14:57 xz.bc
```

## Building a New Binary

The new bitcode can be used for a variety of purposes ranging from informational analyses to hardening and transformation. Eventually, though, you may want to re-create a new, working binary. Here is how to do that.

First, you'll need McSema's runtime libraries that are generated during installation. These are located at the installation prefix of McSema, typically in `/usr/local` on Unix machines. Alternatively, these can be found in the Remill build directory, under `tools/mcsema/mcsema/Arch/X86/Runtime` (for X86). You will also need to link against any libraries that the original program was linked against. For this example, make sure that the liblzma-dev package is installed on your machine:

```shell
sudo apt-get install liblzma-dev
```

When Remill/McSema is installed, so should a prefixed version of clang for the build toolchain. For example, building Remill/McSema with the LLVM 4.0 toolchain should also install `remill-clang-4.0`. If not, you can always find the toolchain-specific version of the LLVM binaries and libraries in the Remill build directory, under `libraries/llvm/bin`.

Now, let's re-create a new `xz` binary and see it in action!

```shell
remill-clang-4.0 -rdynamic -O3 -o xz.new xz.bc /usr/local/lib/libmcsema_rt64-4.0.a -llzma
```

This is a fairly ordinary clang command line; the only thing of note is `/usr/local/lib/libmcsema_rt64-4.0.a`, which is the path to the aforementioned runtime libraries. The `libmcsema_rt64-4.0.a` is the library to use for 64-bit bitcode using the LLVM 4.0 toolchain, and `libmcsema_rt32-4.0.a` is the library to use for 32-bit bitcode using the LLVM 4.0 toolchain. On Windows, these libraries are named `mcsema_rt64-4.0.lib` and `mcsema_rt32-4.0.lib`, respectively.

We can verify that our new binary, `xz.new`, works, and compresses output that can be read by `unxz`:

```shell
$ echo "testing compression" | ./xz.new | unxz
testing compression
```

Command line arguments to `xz.new` also work:

```shell
$ ./xz.new --version
xz (XZ Utils) 5.1.0alpha
liblzma 5.1.0alpha
$ ./xz.new --help
Usage: ./xz.new [OPTION]... [FILE]...
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
