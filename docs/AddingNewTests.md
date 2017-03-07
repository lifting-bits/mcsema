# Adding New Tests

This document describes how to add new tests to mcsema's testing frameworks.

# Integration Tests

The mcsema integration tests are designed to test that mcsema translates real programs correctly and in a reasonable amount of time.

Translation is a two step process: first there is CFG recovery, and then transcription to bitcode. As of mcsema 0.6, CFG recovery requires IDA Pro. To ensure integration tests can run without IDA Pro present, the recovered control flow (.cfg files) are checked into git.

Translation is correct if the following hold:

* Mcsema exits cleanly while translating the binary (e.g. exit code 0).
* The translated bitcode is emitted to a file.
* The bitcode can be re-built to a translated executable.
* The translated executable produces identical output (both on stdin and stderr) as the original. 
* The translated executable exits cleanly (e.g. exit code 0).

Below is a step-by-step guide to adding a new integration test.

## Linux

### Source or Binary?

Tests can start with source code or with a precompiled binary. 

Source-based tests are automatically built to x86 and amd64 architectures and should be contained within a single source file, to avoid modifying the main Makefile.

Binary-based tests start with a precompiled binary that should be placed in its architecture specific directory (either [x86](https://github.com/trailofbits/mcsema/tree/master/tests/linux/x86) or [amd64](https://github.com/trailofbits/mcsema/tree/master/tests/linux/amd64)). The file should end in `.elf` to be detected by the test generation scripts. 

For this example, we'll start with the following source file, to be named `switch.c`:

    #include <stdio.h>
    #include <stdlib.h>

    int main(int argc, const char *argv[]) {

        if(argc < 2) {
          return -1;
        }

        int input = atoi(argv[1]);

        switch(input) {
            case 0: 
                printf("Input was zero\n");
                break;
            case 1: 
                printf("Input was one\n");
                break;
            case 2: 
                printf("Input was two\n");
                break;
            case 4: 
                printf("Input was four\n");
                break;
            case 6: 
                printf("Input was six\n");
                break;
            case 12: 
                printf("Input was twelve\n");
                break;
            case 13: 
                printf("Input was thirteen\n");
                break;
            case 19: 
                printf("Input was nineteen\n");
                break;
            case 255: 
                printf("Input was two hundred fifty-five\n");
                break;
            case 0x12389:
                printf("Really big input:  0x12389\n");
                break;
            case 0x1238A:
                printf("Really big input:  0x1238A\n");
                break;
            case 0x1238B:
                printf("Really big input:  0x1238B\n");
                break;
            case 0x1238C:
                printf("Really big input:  0x1238C\n");
                break;
            case 0x1238D:
                printf("Really big input:  0x1238D\n");
                break;
            case 0x1238F:
                printf("Really big input:  0x1238F\n");
                break;
            case 0x12390:
                printf("Really big input:  0x12390\n");
                break;
            case 0x12391:
                printf("Really big input:  0x12391\n");
                break;
            case 0x12392:
                printf("Really big input:  0x12392\n");
                break;
            case 0x12393:
                printf("Really big input:  0x12393\n");
                break;
            default:
                printf("Unknown input: %d\n", input);
        }
        return 0;
    }

### Generating Expected Output

We need to tell the test generation scripts what output the program should have. To do that, edit [x86/config.json](https://github.com/trailofbits/mcsema/blob/master/tests/linux/x86/config.json) and [amd64/config.json](https://github.com/trailofbits/mcsema/blob/master/tests/linux/amd64/config.json) and add:

    "switch": {
        "_comment": "A test for switch statements, which hits mcsema's jump table handling",
        "switch 1": {
            "_comment": "Executes ./switch 1 [the most simple test case]",
            "args": ["1"]
        },
        "switch 14": {
            "_comment": "Executes ./switch 14 [hits the default case]",
            "args": ["14"]
        },
        "switch 74642": {
            "_comment": "Executes ./switch 74642 [hits the big number case]",
            "args": ["74642"]
        }
    }

The top level name, `"switch"`, has to correspond to the test name.

Any entries that begin with `_`, like `_comment`, are ignored by the test generation scripts, and serve as comments to human readers.

Each entry in the testing block for `"switch"` is a test name, like `"switch 14"`. Inside the test name entry the only required entry is `args`, which is a list specifying command line arguments to pass to the program under test. if no arguments are needed, the list should be the empty list `[]`. 

### Generate the tests

The Makefile in [tests/linux](https://github.com/trailofbits/mcsema/blob/master/tests/linux/Makefile) will generate the CFG files and expected outputs.

IDA Pro is required to generate the pre-computed CFG files.

The Makefile will attempt to find IDA Pro and mcsema using the `IDA_PATH` and `MCSEMA_PATH` environment variables, respectively. If that fails, the Makefile will default to looking for each in their usual locations.

In this example, we'll manually specify the IDA and mcsema paths. To build the new tests, simply type `make all`:

    artem@nessie:/store/artem/git/mcsema/tests/linux$ IDA_PATH=/home/artem/ida-6.9 MCSEMA_PATH=/store/artem/git/mcsema/bin/ make all
    clang-3.8 -m64 -o amd64/hello.elf hello.c
    /store/artem/git/mcsema/bin//mcsema-disass --disassembler /home/artem/ida-6.9/idal64 --arch amd64 --os linux --output amd64/hello.cfg --binary amd64/hello.elf --entrypoint main
    clang-3.8 -m64 -o amd64/stringpool.elf stringpool.c
    /store/artem/git/mcsema/bin//mcsema-disass --disassembler /home/artem/ida-6.9/idal64 --arch amd64 --os linux --output amd64/stringpool.cfg --binary amd64/stringpool.elf --entrypoint main
    clang-3.8 -m64 -o amd64/switch.elf switch.c
    /store/artem/git/mcsema/bin//mcsema-disass --disassembler /home/artem/ida-6.9/idal64 --arch amd64 --os linux --output amd64/switch.cfg --binary amd64/switch.elf --entrypoint main
    /store/artem/git/mcsema/tests/linux//generate_expected_output.py amd64/config.json amd64/expected_outputs.json
    Using temporary directory: /tmp/tmp2KD6RP
    Processing test: ls
    	Processing configuration: default
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/ls.elf', u'-d', u'/usr']
    	Processing configuration: width test
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/ls.elf', u'--width=100', u'-d', u'/usr']
    Processing test: switch
    	Processing configuration: switch 74642
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/switch.elf', u'74642']
    	Processing configuration: switch 1
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/switch.elf', u'1']
    	Processing configuration: switch 14
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/switch.elf', u'14']
    Processing test: hello
    	Processing configuration: default
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/hello.elf']
    Processing test: stringpool
    	Processing configuration: default
    Executing: [u'/store/artem/git/mcsema/tests/linux/amd64/stringpool.elf']
    Saved ground truth to: amd64/expected_outputs.json
    clang-3.8 -m32 -o x86/hello.elf hello.c
    /store/artem/git/mcsema/bin//mcsema-disass --disassembler /home/artem/ida-6.9/idal --arch x86 --os linux --output x86/hello.cfg --binary x86/hello.elf --entrypoint main
    clang-3.8 -m32 -o x86/stringpool.elf stringpool.c
    /store/artem/git/mcsema/bin//mcsema-disass --disassembler /home/artem/ida-6.9/idal --arch x86 --os linux --output x86/stringpool.cfg --binary x86/stringpool.elf --entrypoint main
    clang-3.8 -m32 -o x86/switch.elf switch.c
    /store/artem/git/mcsema/bin//mcsema-disass --disassembler /home/artem/ida-6.9/idal --arch x86 --os linux --output x86/switch.cfg --binary x86/switch.elf --entrypoint main
    /store/artem/git/mcsema/tests/linux//generate_expected_output.py x86/config.json x86/expected_outputs.json
    Using temporary directory: /tmp/tmpdp8QDP
    Processing test: switch
    	Processing configuration: switch 74642
    Executing: [u'/store/artem/git/mcsema/tests/linux/x86/switch.elf', u'74642']
    	Processing configuration: switch 1
    Executing: [u'/store/artem/git/mcsema/tests/linux/x86/switch.elf', u'1']
    	Processing configuration: switch 14
    Executing: [u'/store/artem/git/mcsema/tests/linux/x86/switch.elf', u'14']
    Processing test: hello
    	Processing configuration: default
    Executing: [u'/store/artem/git/mcsema/tests/linux/x86/hello.elf']
    Processing test: stringpool
    	Processing configuration: default
    Executing: [u'/store/artem/git/mcsema/tests/linux/x86/stringpool.elf']
    Saved ground truth to: x86/expected_outputs.json  


### Running the tests

There is one more step needed before these tests will be run by the integration test system: telling the test system to run them.

To do that, edit [tests/integration_test.py](https://github.com/trailofbits/mcsema/blob/master/tests/integration_test.py) and add a new function to the LinuxTest class. Since these tests use the Python `unittest` framework, the name of each function must start with `test`. We'll name this one `testswitch`:

    def testswitch(self):
        self._runX86Test("switch")
        self._runAMD64Test("switch")


Now we can run the tests, by executing `integration_test.py`. These tests will automatically run in Travis-CI upon push to Github.

    $ python integration_test.py
    testHello (__main__.LinuxTest) ... ~
    ~
    ~
    ~
    ~
    ~
    ok
    testStringPool (__main__.LinuxTest) ... ~
    ~
    ~
    ~
    ~
    ~
    ok
    testls (__main__.LinuxTest) ... skipped 'Re-enable after we fix issue #108'
    testswitch (__main__.LinuxTest) ... ~
    ~
    ~
    ~
    ~
    ~
    ~
    ~
    ~
    ~
    ok
    
    ----------------------------------------------------------------------
    Ran 4 tests in 22.087s
    
    OK (skipped=1)

Success, it works! The output tells us the testswitch function ran, and all conditions for a successful test were met.

## Windows

To be determined once the integration test system has been ported to Windows, but it will look a lot like Linux.

# Unit Tests

Currently in flux as we are re-doing the unit testing framework.
