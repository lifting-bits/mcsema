# Using libFuzzer with Mcsema

[libFuzzer](http://blog.llvm.org/2015/04/fuzz-all-clangs.html) is an LLVM-based coverage-guided fuzzing framework, similar to AFL. Using libFuzzer, it's simple to integrate coverage-guided fuzzing: just define a special function, update some build flags, and you have instant coverage-guided fuzzing.

Since libFuzzer works at the LLVM level, we thought, can we apply libFuzzer to mcsema translated bitcode, and use libFuzzer on binaries?

It turns out the answer is yes!

However, the 'yes' comes with caveats. First, mcsema assembly stubs do some things that normal programs should never do (like calculate dynamic return addresses, allocate new stacks, etc). This behavior can conflict with address sanitizer, a feature that libFuzzer uses. Second, mcsema's control flow recovery is frequently wrong on large programs. Since libFuzzer explores new code paths, it has a very high likelihood of triggering a path where control flow recovery is incorrect. This means that some of the bugs found may be artifacts of translation that are not present in the original program.

We hope to improve both of these issues in the future. For now, let's take a look at a proof of concept for using libFuzzer on binary code!

The code we will be fuzzing is a [simple program](../tests/libFuzzer/fuzzme.cc) that tries to dereference user input once it reads the word 'fuzz':

    $ cat fuzzme.cc
    #include <stdio.h>
    #include <stdint.h>
    
    int vulnerable(const char *arg) {
        if(arg[0] == 'f') {
            if(arg[1] == 'u') {
                if(arg[2] == 'z') {
                    if(arg[3] == 'z') {
                        if(arg[4] == '\0') {
                            return 0;
                        } else {
                            // lets deref some user specified memory
                            int** z = (int**)((void*)(arg+4));
                            return **z;
                        }
                    }
                }
            }
        }
        return -1;
    }
    
    #ifdef SOURCE_FUZZ
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
        vulnerable((const char *)Data);
        return 0;  // Non-zero return values are reserved for future use.
    }
    #else
    int main(int argc, const char *argv[]) {
    
        if(argc != 2) {
            printf("Usage:\n");
            printf("%s: <text>\n", argv[0]);
            return 1;
        }
    
        if(0 == vulnerable(argv[1])) {
            printf("Processed correctly\n");
        } else {
            printf("Bad input\n");
        }
    
        return 0;
    }
    #endif

## Prepare

libFuzzer is constantly improving; this guide will use an older version of libFuzzer that comes with LLVM 3.8, because that is the LLVM version used by mcsema.

For this guide, we will assume that mcsema was built in `$MCSEMA_DIR`, and all operations take place in [`$MCSEMA_DIR/mcsema/tests/libFuzzer`](../tests/libFuzzer).

## Preparing and verifying libFuzzer

First, run the `buildFuzzer.sh` script to generate libFuzzer objects. This should generate several files matching the pattern `Fuzzer*.o`:

    $ ./buildFuzzer.sh
    $ ls -1 Fuzzer*.o
    FuzzerCrossOver.o
    FuzzerDriver.o
    FuzzerInterface.o
    FuzzerIO.o
    FuzzerLoop.o
    FuzzerMain.o
    FuzzerMutate.o
    FuzzerSanitizerOptions.o
    FuzzerSHA1.o
    FuzzerTraceState.o
    FuzzerUtil.o

Next, let's build a normal, non-mcsema version of our test to make sure libFuzzer works.    

    clang++-3.8 -DSOURCE_FUZZ -o fuzzme fuzzme.cc Fuzzer*.o -fsanitize=address -fsanitize-coverage=edge

The `-fsanitize` and `-fsanitize-coverage` arguments are standard arguments to instrument the built code for libFuzzer. The `-DSOURCE_FUZZ` argument sets a define to make sure the required `LLVMFuzzerTestOneInput` is emitted by our test code. For more details, see the [libFuzzer documentation](http://releases.llvm.org/3.8.0/docs/LibFuzzer.html).


Now, let's run the source-based libFuzzer executable to make sure it works. Very quickly, you should see output similar to the following:

    $ ./fuzzme
    Seed: 1013786530
    PreferSmall: 1
    #0      READ   units: 1 exec/s: 0
    #1      INITED cov: 5 units: 1 exec/s: 0
    #437    NEW    cov: 8 units: 2 exec/s: 0 L: 64 MS: 0
    #620609 NEW    cov: 11 units: 3 exec/s: 620609 L: 64 MS: 3 ShuffleBytes-ChangeASCIIInt-ChangeByte-
    #978396 NEW    cov: 13 units: 4 exec/s: 978396 L: 58 MS: 5 ShuffleBytes-ShuffleBytes-CrossOver-ChangeASCIIInt-ChangeByte-
    ASAN:DEADLYSIGNAL
    =================================================================
    ==21762==ERROR: AddressSanitizer: SEGV on unknown address 0x000000007566 (pc 0x0000004eebf6 bp 0x7fff690a6580 sp 0x7fff690a64f0 T0)
        #0 0x4eebf5  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4eebf5)
        #1 0x4eed2d  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4eed2d)
        #2 0x4f464a  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4f464a)
        #3 0x4f57de  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4f57de)
        #4 0x4f5db7  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4f5db7)
        #5 0x4f0546  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4f0546)
        #6 0x4ef232  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4ef232)
        #7 0x4ef183  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4ef183)
        #8 0x7f7cb7ce482f  (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
        #9 0x41a3b8  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x41a3b8)
    
    AddressSanitizer can not provide additional info.
    SUMMARY: AddressSanitizer: SEGV (/store/artem/git/mcsema/tests/libFuzzer/fuzzme+0x4eebf5)
    ==21762==ABORTING
    DEATH:
    0x66,0x75,0x7a,0x7a,0x66,0x75,
    fuzzfu
    artifact_prefix='./'; Test unit written to ./crash-643f1d111ee9b982169c2278898ce3228c4c6e2e
    Base64: ZnV6emZ1


Good news! libFuzzer found our magic prefix of 'fuzz' and triggered the error.

## Building The Binary

Mcsema operates on binaries, so let's give it a binary to translate and make sure it works:

    $ clang++-3.8 -o fuzzme.binary fuzzme.cc
    $ ./fuzzme.binary
    Usage:
    ./fuzzme.binary: <text>
    $ ./fuzzme.binary aaaaa
    Bad input
    $ ./fuzzme.binary fuzza
    Segmentation fault (core dumped)

Great, the binary runs and exhibits the bad condition we want to fuzz for. Now let's lift it into bitcode!

## Lifting the Binary

The function we really want to lift isn't `main`, but `vulnerable`. Since the binary is C++ based, `vulnerable`'s symbol name has been mangled. Let's find the [mangled name](https://en.wikipedia.org/wiki/Name_mangling) we need to use as the entry point.

    $ nm fuzzme.binary | grep vulnerable
    00000000004005f0 T _Z10vulnerablePKc

Now, let's disassemble the binary, starting with the entry point of `_Z10vulnerablePKc`.

    $ ../../bin/mcsema-disass --disassembler ~/ida-6.9/idal64 --arch amd64 --os linux --entrypoint _Z10vulnerablePKc --binary fuzzme.binary --output fuzzme.cfg --log_file fuzzme.log 

And once we have the control flow graph, we can convert it to bitcode:

    $ ../../bin/mcsema-lift --arch amd64 --os linux --entrypoint _Z10vulnerablePKc --cfg fuzzme.cfg --output fuzzme.bc
    ... lots of outputs ...
    Adding entry point: _Z10vulnerablePKc
    _Z10vulnerablePKc is implemented by sub_4005f0 

## Using libFuzzer on mcsema bitcode

To use libFuzzer, we need a function named `LLVMFuzzerTestOneInput`, so we have to create a small driver program to call into our bitcode. We have included a pre-made one, aptly named `driver.cc`:

    $ cat driver.cc
    #include <stdint.h>
    #include <stdlib.h>
    
    extern int vulnerable(const char *input);
    
    extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        vulnerable((const char *)(data));
        return 0;
    }

The driver just says that there is an external function with the signature `int vulnerable(const char *)` (this is the function we lifted), and calls it.

Now let's combine the driver, our bitcode, mcsema assembly stubs, and libFuzzer instrumentation into one program:

    $ clang++-3.8 -O3 -o fuzzme.mcsema driver.cc fuzzme.bc ../../generated/ELF_64_linux.S Fuzzer*.o -fsanitize=address -fsanitize-coverage=edge

We can now try fuzzing the newly instrumented binary:

    $ ./fuzzme.mcsema
    Seed: 1024766608
    PreferSmall: 1
    #0      READ   units: 1 exec/s: 0
    #1      INITED cov: 5 units: 1 exec/s: 0
    #742    NEW    cov: 8 units: 2 exec/s: 0 L: 64 MS: 0
    #238510 NEW    cov: 11 units: 3 exec/s: 0 L: 5 MS: 4 CrossOver-InsertByte-EraseByte-ChangeByte-
    #252530 NEW    cov: 13 units: 4 exec/s: 0 L: 11 MS: 4 ShuffleBytes-InsertByte-CrossOver-ChangeBit-
    ASAN:DEADLYSIGNAL
    =================================================================
    ==21840==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0000004ef9f0 bp 0x000000000001 sp 0x7f357e7bd99c T0)
        #0 0x4ef9ef  (/store/artem/git/mcsema/tests/libFuzzer/fuzzme.mcsema+0x4ef9ef)
    
    AddressSanitizer can not provide additional info.
    SUMMARY: AddressSanitizer: SEGV (/store/artem/git/mcsema/tests/libFuzzer/fuzzme.mcsema+0x4ef9ef)
    ==21840==ABORTING
    DEATH:
    0x66,0x75,0x7a,0x7a,0x75,0xf,0xf,0x3b,0x3b,0x66,0x66,
    fuzzu\x0f\x0f;;ff
    artifact_prefix='./'; Test unit written to ./crash-9991751ea97f13a1b7eeeb9e54c69be96cc782f7
    Base64: ZnV6enUPDzs7ZmY=


Success! It finds crashes with the same `fuzz` prefix as before.

## Remarks

As we mentioned in the introduction, mcsema generated bitcode and assembly stubs are not quite compatible with address sanitizer because they do things that normal programs should not do. The `-O3` in the final command line is necessary to produce code where the fuzzer-generated segfault can be reported. Try the same command line with `-O0`: libFuzzer will find the bug, but will not be able to properly report that it was found.

Using mcsema and libFuzzer on large programs is still a work in progress. We think that it can work, but currently CFG recovery is not accurate enough to use libFuzzer and mcsema on the normal libFuzzer samples. We hope to change that in the future.

