Usage of MC-Semantics Standalone Tools
======================================

Some of the tools and their associated configuration files are documented below:

## get_cfg.py

The get_cfg.py script is an IDAPython script that will use IDA Pro to recover a control flow graph from a binary. It has been tested on Windows DLLs and COFF object (.obj) files. 

The script is meant to be run in batch mode and not used interactively from IDA. The following examples are all takes from the existing demos and use IDA in batch mode to recover control flow graphs. 

### Limitations

The script has only been tested with IDA 6.5 for Windows, but should work for other versions and platforms.

While IDA is very good at recovering control flow, it is not perfect. Sometimes IDA will mismatch code and data. Other times, IDA will think constant values are pointers. The get_cfg.py script will believe whatever IDA thinks. 

It is difficult to see if the script threw an exception. IDA will just exit, producing a zero-sized CFG. At that point one should run IDA with a startup script, but not in batch mode.

### Usage

In the following examples, the variable `%IDA_PATH%` corresponds to the path of the main IDA Pro executable. In my case, it is mapped to `"C:\Program Files\IDA 6.5"`. 

IDA Invocation command line:

     C:\dev\llvm-new\mc-sema\tests>"%IDA_PATH%\idaq.exe" -S"C:\dev\llvm-new\mc-sema\bin_descend\get_cfg.py --help" demo_test1.obj

An binary (in this case demo_test1.obj) or existing IDB is necessary for IDA to load the Python interpreter. 

Usage Text:

    usage: get_cfg.py [-h] [--batch]
                      [--entry-symbol [ENTRY_SYMBOL [ENTRY_SYMBOL ...]]]
                      [-o OUTPUT] [-s [STD_DEFS [STD_DEFS ...]]]
                      [-e EXPORTS_TO_LIFT] [--make-export-stubs]
                      [--exports-are-apis] [-d]
    
    optional arguments:
      -h, --help            show this help message and exit
      --batch               Indicate the script is running in batch mode
      --entry-symbol [ENTRY_SYMBOL [ENTRY_SYMBOL ...]]
                            Symbol(s) to start disassembling from
      -o OUTPUT, --output OUTPUT
                            The output control flow graph recovered from this file
      -s [STD_DEFS [STD_DEFS ...]], --std-defs [STD_DEFS [STD_DEFS ...]]
                            std_defs file: definitions and calling conventions of
                            imported functions and data
      -e EXPORTS_TO_LIFT, --exports-to-lift EXPORTS_TO_LIFT
                            A file containing a exported functions to lift, one
                            per line. If not specified, all exports will be
                            lifted.
      --make-export-stubs   Generate a .bat/.c/.def combination to provide export
                            symbols. Use this if you're lifting a DLL and want to
                            re-export the same symbols
      --exports-are-apis    Exported functions are defined in std_defs. Useful
                            when lifting DLLs
      -d, --debug           Enable verbose debugging mode


### Examples

All examples are taken from the functionality demos. 

The variable `%GET_CFG_PY%` is the path of the `get_cfg.py` script. 

The variable `%STD_DEFS%` is the path of the standard api definitions file, set to `..\std_defs\std_defs.txt`.

Recover control flow from `demo_test1.obj` starting at symbol `start`. Save the output to `demo_test1.cfg`:

`"%IDA_PATH%\idaq.exe" -B -S"%GET_CFG_PY% --batch --entry-symbol start --output demo_test1.cfg" demo_test1.obj`

Recover control flow from `demo_test4.obj` starting at symbol `_doTrans`. Use the file `%STD_DEFS%` as the external API definition file. Output the cfg to `demo_test4.cfg`.

`"%IDA_PATH%\idaq.exe" -B -S"%GET_CFG_PY% --entry-symbol _doTrans --batch --output demo_test4.cfg --std-defs \"%STD_DEFS%\" " demo_test4.obj`

Recover control flow from `demo_dll_5.dll`. Start recovery at the list of functions specified in the text file `demo_dll_5_to_lift.txt`. Use `%STD_DEFS%` as the external API definitions file. Save the result to `demo_dll_5.cfg`.

`"%IDA_PATH%\idaq.exe" -B -S"%GET_CFG_PY% --batch --std-defs \"%STD_DEFS%\" --exports-to-lift demo_dll_5_to_lift.txt --output demo_dll_5.cfg" demo_dll_5.dll`

Recover control flow from `demo_dll_6.dll`. Start recovery at the symbol `get_value`. Use both `demo_6_defs.txt` and `%STD_DEFS%` as the external API definition files. Save the result to `demo_dll_6.cfg`.

`"%IDA_PATH%\idaq.exe" -B -S"%GET_CFG_PY% --batch --std-defs \"%STD_DEFS%\" demo_6_defs.txt --entry-symbol get_value --output demo_dll_6.cfg" demo_dll_6.dll`

## bin_descend

bin_descend is a recursive descent disassembler and control flow recovery tool. As input, bin_descend accepts COFF object files and Windows PE DLLs. To accurately recover control flow, it is imperative that relocation information *not* be stripped from the input file.

The output file is named `<input name without extension>.cfg`. That is, an input of `foo.obj` will produce `foo.cfg`.

When recovering control flow, bin_descend uses certain heuristics to attempt accurate control flow recovery:

* Relocated immediate values in code (e.g. PUSH imm32) that point to the code section are assumed to be function pointers. These will be added to the list of entry points from which to recover control flow.
* Relocated values in the data section that point to the code section are assumed to be function pointers. These will be added to the list of entry points from which to recover control flow.
* Additionally, relocated function pointers in the data section are assumed to be used as callbacks. A thunk that takes current register state and transforms it into a translator specific register context will automatically be created for these functions, and used in place of the function when it referenced not by a direct call.
* Relocated immediate values in code (e.g. PUSH imm32) that point to the data section are assumed to be data values.
* Relocated immediate values in the data section that point to the data section are assumed to be data values.

### Limitations

COFF files will have several sections based at address zero. As there is no specification for how to assign addresses, we will assign addresses to sections in the order in which they are processed. This usually matches the address what other tools (e.g. IDA Pro)  select, but not always. It is recommended that the entry point for COFF object should be specified by `-entry-symbol` and not `-e`.

### Usage

     C:\>bin_descend -help
     
     OVERVIEW: binary recursive descent
     USAGE: bin_descend.exe [options]
     
     OPTIONS:
       -d                                                         - Print debug information
       -e=<VA>                                                    - Entry point
       -entry-symbol=<symbol1,symbol2,symbol3,...>                - Entry point symbol(s)
       -func-map=<std_defs.txt,custom_defs.txt,other_mapping.txt> - Function map files
       -help                                                      - Display available options (-help-hidden for more)
       -i=<filename>                                              - Input filename
       -ignore-native-entry-points                                - Ignore any exported functions not explicitly specified via -e or -entry-symbol
       -mc-x86-disable-arith-relaxation                           - Disable relaxation of arithmetic instruction for X86
       -mtriple=<target triple>                                   - Target Triple
       -stats                                                     - Enable statistics output from program
       -v=<level>                                                 - Verbosity level
       -version                                                   - Display the version of this program
       -x86-asm-syntax                                            - Choose style of code to emit from X86 backend:
         =att                                                     -   Emit AT&T-style assembly
         =intel                                                   -   Emit Intel-style assembly


* `-d`: This flag will enable output of extra debugging information to standard out.
* `-e=<VA>`: Specify the entry point address where disassembly will begin. This value should be a virtual address in the target module. Both decimal and hex values are accepted. Hex values must be prefixed with 0x or 0X.
* `-entry-symbol`: Specify entry point symbol(s) from which to start disassembly. This is particualrly useful for COFF files where several sections based at address zero will be rebased during control flow recovery. 
* `-func-map=<std_defs.txt,custom_defs.txt,other_mapping.txt>`: Location of file(s) that specify arguments and calling conventions of externally referenced functions. Externally referenced functions are those that are not a part of the translated code: APIs, functions in other compilation units, etc. The file `std_defs.txt` is a pre-existing define file that provides definitions for most of the Win32 API and the standard C library. 
* `-help`: Display the help screen above.
* `-i=<filename>`: Specify the input file. This should be a COFF object or a Window PE DLL.
* `-ignore-native-entry-points`: Do not process any exported functions other than the one specified by `-e` or `-entry-symbol`. This option should be used when processing DLLs that import C runtime initialization code or include exports unrelated to the one you are trying to lift.
* `-mc-x86-disable-arith-relaxation`: 
* `-mtriple=<target triple>`: Specify the target triple (e.g. i686-pc-win32, i686-pc-linux-gnu) of the input file. This option should be used when processing Windows object files on Linux, or vice versa.
* `-stats`:
* `-v=<level>`: 
* `-version`: Display the version of bin_descend.
* `-x86-asm-syntax`: Chose whether assembly output will use ATT or Intel syntax.

### Examples

These examples are taken from the tests present in `mc-sema/tests`.

Recover control flow for `demo_test1.obj` starting at symbol `start` and enable debugging output:

`bin_descend.exe -d -entry-symbol=start -i=demo_test1.obj`

Recover control flow for `demo_test4.obj` starting at symbol `_doTrans`, enable debugging, and specify a definitions file for external functions (to properly link API calls):

`bin_descend.exe -d -func-map=std_defs.txt -entry-symbol=_doTrans -i=demo_test4.obj`

Recover control flow for `sailboat.obj` starting at symbol `_keycomp`, enable debugging, and specify two external function definition files:

`bin_descend.exe -d -func-map=sailboat.txt,std_defs.txt -entry-symbol=_keycomp -i=sailboat.obj`

Recover control flow from `demo_dll_1.dll`, starting at symbol `HelloWorld`, enable debugging, specify an external function definition, and ignore all entry points other than `HelloWorld`:

`bin_descend.exe -d -entry-symbol=HelloWorld -ignore-native-entry-points=true -i=demo_dll_1.dll -func-map=std_defs.txt`


## cfg_to_bc 

The cfg_to_bc tool will take a control flow graph in the format produced by bin_descend, and translate it to LLVM bitcode. The resulting bitcode will have a driver function, specified by `-driver-name`. The driver is an exported function that takes place of the entrypoint in the original code. If the original function accepted arguments as 32-bit values pushed onto the stack, a stub to place these into a register context can be automatically generated by specifying the argument count via `-driver-argc`. In case of other calling conventions, a raw driver that accepts a complete register context can be defined via `-driver-raw`.


The CFG is in Google protocol buffer format. The definition of the protocol is in `mc-sema/peToCFG/CFG.proto`. The CFG does not have to be created by bin_descend, but it can be created by any tool (e.g. IDA Python) that can write to the protocol buffer format. The control flow recovery and translation portions were explicitly designed to be separable. 

### Limitations

While many x86 instructions are supported, there are still those which are not supported. The biggest unsupported parts are about half of the FPU instructions and SSE instructions other than MOVDQA. The infrastructure to support translation of these instructions (e.g. register state) exists, and its a simple matter of writing the translation.


### Usage (some options omitted because they are inserted by LLVM)

    OVERVIEW: CFG to LLVM
    USAGE: cfg_to_bc [options]
    
    OPTIONS:
      -driver=<<driver name>,<symbol | ep address>,<'raw' | argument count>,<'return' | 'noreturn'>,< calling convention: 'C', 'E', 'F'>> - Describe externally visible entry points
      -help                                                                                                                               - Display available options (-help-hidden for more)
      -i=<<filename>>                                                                                                                     - Input filename
      -ignore-unsupported                                                                                                                 - Ignore unsupported instructions
      -m                                                                                                                                  - Output native module format
      -mc-x86-disable-arith-relaxation                                                                                                    - Disable relaxation of arithmetic instruction for X86
      -mtriple=<target triple>                                                                                                            - Target Triple
      -o=<filename>                                                                                                                       - Output filename
      -verify-scev                                                                                                                        - Verify ScalarEvolution's backedge taken counts (slow)
      -version                                                                                                                            - Display the version of this program
      -x86-asm-syntax                                                                                                                     - Choose style of code to emit from X86 backend:
        =att                                                                                                                              -   Emit AT&T-style assembly
        =intel                                                                                                                            -   Emit Intel-style assembly

* `-driver`: This describes an externally visible entry point in the final bitcode. The `-driver` commandline may be repeated for multiple entry points into the bitcode. Each invocation rquires a `driver name`, an exported `symbol or entry point address` to bind to, an `argument count` or `'raw'` if the driver has an esoteric calling convention, whether the driver returns or does not return, and a calling convention for the driver function. This option is best understood by looking at the examples.
* `-help`: display the help screen.
* `-i=<<filename>>`: Specify the control flow graph used that will be translated to llvm bitcode. The CFG must be in serialized Google protocol buffer format, with the protocol specified in `CFG.proto`.
* `-ignore-unsupported`: Don't stop when encountering an unsupported instruction, but output a message, ignore it, and keep translating.
* `-m`: Output the control flow graph of every function in the module in graphviz (aka dot) format. This is useful for visualizing the translated code to locate any translation errors.  
* `-mc-x86-disable-arith-relaxation`: 
* `-mtriple=<target triple>`: Specify the target triple (e.g. i686-pc-win32, i686-pc-linux-gnu) of the input file. This option should be used when processing Windows object files on Linux, or vice versa.
* `-o=<filename>`: The output filename. This file will contain LLVM bitcode.
* `-x86-asm-syntax`: Chose whether assembly output will use ATT or Intel syntax.

### Examples

These examples are taken from the tests present in `mc-sema/tests`.

Convert the control flow graph in `demo_test1.cfg` into bitcode stored in `demo_test1.bc`. Specify that the driver name will be `demo1_entry`, that it will point to the `start` entry point, and that it will accept a `raw` register context as an argument, and that it `return`s.

`cfg_to_bc.exe -i demo_test1.cfg -driver=demo1_entry,start,raw,return,C -o demo_test1.bc`

Convert the control flow graph in `demo_test3.cfg` into bitcode stored in `demo_test3.bc`. Specify that the driver name will be `demo3_entry`, that it will point to the `_demo3` entry point, and that it will have `2` arguments that are pushed onto the stack.

`cfg_to_bc.exe -i demo_test3.cfg -driver=demo3_entry,_demo3,2,return,C -o demo_test3.bc`

Convert the control flow graph in `demo_dll_1.cfg` into bitcode stored in `demo_dll_1.bc`. Specify that the driver name will be `demo_dll_1_driver`, that it will point to the `HelloWorld` symbol, and that it will have zero arguments.

`cfg_to_bc.exe -i demo_dll_1.cfg -driver=demo_dll_1_driver,HelloWorld,0,return,C -o demo_dll_1.bc`

Convert the control flow graph in `demo_dll_5.cfg` into bitcode stored in `demo_dll_5.bc`. There will be three drivers. The first will be named `d_who_spartacus`, which will point to the entry symbol `who_is_spartacus`. It will have zero arguments and it returns. The second driver will be named `d_who_spartacus2`, point to the entry symbol `who_is_spartacus2`, take zero arguments, and return. The third driver will be named `d_get_response`, it will point to the original entry point `get_response`, take zero arguments, and return.

`cfg_to_bc.exe -i demo_dll_5.cfg -driver=d_who_spartacus,who_is_spartacus,0,return,C -driver=d_who_spartacus2,who_is_spartacus2,0,return,C -driver=d_get_response,get_response,0,return,C -o demo_dll_5.bc`

## testSemantics

The testSemantics application is used to verify that instruction translation semantics are working correctly.

There are tests for instructions that are not currently supported. This is by design, so when the instructions are added to the translator the tests for them already exist.

testSemantics will read from a file named `tests.out` in the directory of execution. The `tests.out` file contains ground truth about intstruction semantics. A `tests.out` is automatically generated when mc-sema is built.

By default the `tests.out` file is in `<mc-sema code>\build\mc-sema\validator\valTest\<Debug or Release>`.

### Examples

This is the output of testSemantics as of July 2014. Not all instruction tests complete successfully; the floating point tests are there for when the instructions are implemented in the translator.

    C:\git\llvm-lift\build\mc-sema\validator\valTest\Debug>..\..\testSemantics\Debug\testSemantics.exe

    [==========] Running 426 tests from 1 test case.
    [----------] Global test environment set-up.
    [----------] 426 tests from ModuleTest
    [ RUN      ] ModuleTest.AAA
    [       OK ] ModuleTest.AAA (1997 ms)
    [ RUN      ] ModuleTest.AAD8i8
    [       OK ] ModuleTest.AAD8i8 (62 ms)
    [ RUN      ] ModuleTest.AAM8i8
    [       OK ] ModuleTest.AAM8i8 (78 ms)
    [ RUN      ] ModuleTest.AAS
    [       OK ] ModuleTest.AAS (63 ms)
    [ RUN      ] ModuleTest.ABS_F
    Unsupported!
    0 	fabs
    21
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(1898): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.ABS_F (0 ms)
    [ RUN      ] ModuleTest.ADC16i16
    [       OK ] ModuleTest.ADC16i16 (78 ms)
    [ RUN      ] ModuleTest.ADC16ri
    [       OK ] ModuleTest.ADC16ri (78 ms)
    [ RUN      ] ModuleTest.ADC16rr
    [       OK ] ModuleTest.ADC16rr (78 ms)
    [ RUN      ] ModuleTest.ADC32i32
    [       OK ] ModuleTest.ADC32i32 (62 ms)
    [ RUN      ] ModuleTest.ADC32ri
    [       OK ] ModuleTest.ADC32ri (78 ms)
    [ RUN      ] ModuleTest.ADC32rr
    [       OK ] ModuleTest.ADC32rr (78 ms)
    [ RUN      ] ModuleTest.ADC8i8
    [       OK ] ModuleTest.ADC8i8 (78 ms)
    [ RUN      ] ModuleTest.ADC8ri
    [       OK ] ModuleTest.ADC8ri (63 ms)
    [ RUN      ] ModuleTest.ADC8rr
    [       OK ] ModuleTest.ADC8rr (78 ms)
    [ RUN      ] ModuleTest.ADD16i16
    [       OK ] ModuleTest.ADD16i16 (78 ms)
    [ RUN      ] ModuleTest.ADD16ri
    [       OK ] ModuleTest.ADD16ri (62 ms)
    [ RUN      ] ModuleTest.ADD16rm
    [       OK ] ModuleTest.ADD16rm (78 ms)
    [ RUN      ] ModuleTest.ADD16rr
    [       OK ] ModuleTest.ADD16rr (78 ms)
    [ RUN      ] ModuleTest.ADD32i32
    [       OK ] ModuleTest.ADD32i32 (78 ms)
    [ RUN      ] ModuleTest.ADD32mr
    [       OK ] ModuleTest.ADD32mr (78 ms)
    [ RUN      ] ModuleTest.ADD32ri
    [       OK ] ModuleTest.ADD32ri (62 ms)
    [ RUN      ] ModuleTest.ADD32rr
    [       OK ] ModuleTest.ADD32rr (78 ms)
    [ RUN      ] ModuleTest.ADD8i8
    [       OK ] ModuleTest.ADD8i8 (94 ms)
    [ RUN      ] ModuleTest.ADD8ri
    [       OK ] ModuleTest.ADD8ri (78 ms)
    [ RUN      ] ModuleTest.ADD8rr
    [       OK ] ModuleTest.ADD8rr (78 ms)
    [ RUN      ] ModuleTest.ADD_F32m
    [       OK ] ModuleTest.ADD_F32m (109 ms)
    [ RUN      ] ModuleTest.ADD_F64m
    [       OK ] ModuleTest.ADD_F64m (94 ms)
    [ RUN      ] ModuleTest.ADD_FST0r
    [       OK ] ModuleTest.ADD_FST0r (93 ms)
    [ RUN      ] ModuleTest.ADD_FrST0
    [       OK ] ModuleTest.ADD_FrST0 (78 ms)
    [ RUN      ] ModuleTest.AND16i16
    [       OK ] ModuleTest.AND16i16 (93 ms)
    [ RUN      ] ModuleTest.AND16mi
    [       OK ] ModuleTest.AND16mi (78 ms)
    [ RUN      ] ModuleTest.AND16mr
    [       OK ] ModuleTest.AND16mr (78 ms)
    [ RUN      ] ModuleTest.AND16ri
    [       OK ] ModuleTest.AND16ri (63 ms)
    [ RUN      ] ModuleTest.AND16rr
    [       OK ] ModuleTest.AND16rr (78 ms)
    [ RUN      ] ModuleTest.AND32i32
    [       OK ] ModuleTest.AND32i32 (78 ms)
    [ RUN      ] ModuleTest.AND32mr
    [       OK ] ModuleTest.AND32mr (62 ms)
    [ RUN      ] ModuleTest.AND32ri
    [       OK ] ModuleTest.AND32ri (63 ms)
    [ RUN      ] ModuleTest.AND32rr
    [       OK ] ModuleTest.AND32rr (78 ms)
    [ RUN      ] ModuleTest.AND8i8
    [       OK ] ModuleTest.AND8i8 (62 ms)
    [ RUN      ] ModuleTest.AND8mi
    [       OK ] ModuleTest.AND8mi (94 ms)
    [ RUN      ] ModuleTest.AND8mr
    [       OK ] ModuleTest.AND8mr (78 ms)
    [ RUN      ] ModuleTest.AND8ri
    [       OK ] ModuleTest.AND8ri (62 ms)
    [ RUN      ] ModuleTest.AND8rr
    [       OK ] ModuleTest.AND8rr (78 ms)
    [ RUN      ] ModuleTest.BSWAP32r
    [       OK ] ModuleTest.BSWAP32r (62 ms)
    [ RUN      ] ModuleTest.CDQ
    [       OK ] ModuleTest.CDQ (78 ms)
    [ RUN      ] ModuleTest.CLC
    [       OK ] ModuleTest.CLC (63 ms)
    [ RUN      ] ModuleTest.CLD
    [       OK ] ModuleTest.CLD (78 ms)
    [ RUN      ] ModuleTest.CMOVA16rr
    [       OK ] ModuleTest.CMOVA16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVA32rm
    [       OK ] ModuleTest.CMOVA32rm (78 ms)
    [ RUN      ] ModuleTest.CMOVA32rr
    [       OK ] ModuleTest.CMOVA32rr (62 ms)
    [ RUN      ] ModuleTest.CMOVAE16rr
    [       OK ] ModuleTest.CMOVAE16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVAE32rr
    [       OK ] ModuleTest.CMOVAE32rr (63 ms)
    [ RUN      ] ModuleTest.CMOVB16rr
    [       OK ] ModuleTest.CMOVB16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVB32rr
    [       OK ] ModuleTest.CMOVB32rr (62 ms)
    [ RUN      ] ModuleTest.CMOVBE16rr
    [       OK ] ModuleTest.CMOVBE16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVBE32rr
    [       OK ] ModuleTest.CMOVBE32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVE16rr
    [       OK ] ModuleTest.CMOVE16rr (62 ms)
    [ RUN      ] ModuleTest.CMOVE32rr
    [       OK ] ModuleTest.CMOVE32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVG16rr
    [       OK ] ModuleTest.CMOVG16rr (63 ms)
    [ RUN      ] ModuleTest.CMOVG32rr
    [       OK ] ModuleTest.CMOVG32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVGE16rr
    [       OK ] ModuleTest.CMOVGE16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVGE32rr
    [       OK ] ModuleTest.CMOVGE32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVL16rr
    [       OK ] ModuleTest.CMOVL16rr (62 ms)
    [ RUN      ] ModuleTest.CMOVL32rr
    [       OK ] ModuleTest.CMOVL32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVLE16rr
    [       OK ] ModuleTest.CMOVLE16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVLE32rr
    [       OK ] ModuleTest.CMOVLE32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVNE16rr
    [       OK ] ModuleTest.CMOVNE16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVNE32rr
    [       OK ] ModuleTest.CMOVNE32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVNO16rr
    [       OK ] ModuleTest.CMOVNO16rr (63 ms)
    [ RUN      ] ModuleTest.CMOVNO32rr
    [       OK ] ModuleTest.CMOVNO32rr (62 ms)
    [ RUN      ] ModuleTest.CMOVNP16rr
    [       OK ] ModuleTest.CMOVNP16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVNP32rr
    [       OK ] ModuleTest.CMOVNP32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVNS16rr
    [       OK ] ModuleTest.CMOVNS16rr (62 ms)
    [ RUN      ] ModuleTest.CMOVNS32rr
    [       OK ] ModuleTest.CMOVNS32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVO16rr
    [       OK ] ModuleTest.CMOVO16rr (78 ms)
    [ RUN      ] ModuleTest.CMOVO32rr
    [       OK ] ModuleTest.CMOVO32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVP16rr
    [       OK ] ModuleTest.CMOVP16rr (63 ms)
    [ RUN      ] ModuleTest.CMOVP32rr
    [       OK ] ModuleTest.CMOVP32rr (78 ms)
    [ RUN      ] ModuleTest.CMOVS16rr
    [       OK ] ModuleTest.CMOVS16rr (62 ms)
    [ RUN      ] ModuleTest.CMOVS32rr
    [       OK ] ModuleTest.CMOVS32rr (78 ms)
    [ RUN      ] ModuleTest.CMP16mi
    [       OK ] ModuleTest.CMP16mi (63 ms)
    [ RUN      ] ModuleTest.CMP16rr
    [       OK ] ModuleTest.CMP16rr (78 ms)
    [ RUN      ] ModuleTest.CMP32i32
    [       OK ] ModuleTest.CMP32i32 (78 ms)
    [ RUN      ] ModuleTest.CMP32ri
    [       OK ] ModuleTest.CMP32ri (62 ms)
    [ RUN      ] ModuleTest.CMP32rr
    [       OK ] ModuleTest.CMP32rr (78 ms)
    [ RUN      ] ModuleTest.CMP8rr
    [       OK ] ModuleTest.CMP8rr (78 ms)
    [ RUN      ] ModuleTest.CMPXCHG16r
    [       OK ] ModuleTest.CMPXCHG16r (78 ms)
    [ RUN      ] ModuleTest.CMPXCHG32rm
    [       OK ] ModuleTest.CMPXCHG32rm (78 ms)
    [ RUN      ] ModuleTest.CMPXCHG32rr
    [       OK ] ModuleTest.CMPXCHG32rr (62 ms)
    [ RUN      ] ModuleTest.CMPXCHG8rr
    [       OK ] ModuleTest.CMPXCHG8rr (78 ms)
    [ RUN      ] ModuleTest.Cmp32RR1
    [       OK ] ModuleTest.Cmp32RR1 (78 ms)
    [ RUN      ] ModuleTest.Cmp32RR2
    [       OK ] ModuleTest.Cmp32RR2 (63 ms)
    [ RUN      ] ModuleTest.Cmpxch16RR
    [       OK ] ModuleTest.Cmpxch16RR (78 ms)
    [ RUN      ] ModuleTest.Composite1
    [       OK ] ModuleTest.Composite1 (78 ms)
    [ RUN      ] ModuleTest.Composite2
    [       OK ] ModuleTest.Composite2 (78 ms)
    [ RUN      ] ModuleTest.DEC16r
    [       OK ] ModuleTest.DEC16r (78 ms)
    [ RUN      ] ModuleTest.DEC32r
    [       OK ] ModuleTest.DEC32r (62 ms)
    [ RUN      ] ModuleTest.DEC8r
    [       OK ] ModuleTest.DEC8r (78 ms)
    [ RUN      ] ModuleTest.DIV_F32m
    [       OK ] ModuleTest.DIV_F32m (125 ms)
    [ RUN      ] ModuleTest.DIV_F64m
    [       OK ] ModuleTest.DIV_F64m (94 ms)
    [ RUN      ] ModuleTest.DIV_FrST0
    [       OK ] ModuleTest.DIV_FrST0 (93 ms)
    [ RUN      ] ModuleTest.DIV_PFrST0
    [       OK ] ModuleTest.DIV_PFrST0 (125 ms)
    [ RUN      ] ModuleTest.DIV_ST0Fr
    [       OK ] ModuleTest.DIV_ST0Fr (125 ms)
    [ RUN      ] ModuleTest.ENTER
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(1562): error: Value of: in->EBP
      Actual: 0
    Expected: out->EBP
    Which is: 68264312
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(1572): error: Value of: in->AF
      Actual: 1
    Expected: out->AF
    Which is: 0
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(1592): error: Value of: in->ZF
      Actual: 0
    Expected: out->ZF
    Which is: 1
    [  FAILED  ] ModuleTest.ENTER (93 ms)
    [ RUN      ] ModuleTest.F2XM1
    Unsupported!
    0 	f2xm1
    734
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2398): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.F2XM1 (16 ms)
    [ RUN      ] ModuleTest.FABS
    Unsupported!
    0 	fabs
    21
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2403): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FABS (16 ms)
    [ RUN      ] ModuleTest.FADDP
    [       OK ] ModuleTest.FADDP (140 ms)
    [ RUN      ] ModuleTest.FADDP_rST0
    [       OK ] ModuleTest.FADDP_rST0 (109 ms)
    [ RUN      ] ModuleTest.FBLD
    Unsupported!
    18 	fbld	(%edi)
    745
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2418): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FBLD (0 ms)
    [ RUN      ] ModuleTest.FBSTP
    Unsupported!
    18 	fbstp	(%edi)
    746
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2423): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FBSTP (16 ms)
    [ RUN      ] ModuleTest.FCHS
    Unsupported!
    0 	fchs
    354
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2428): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCHS (0 ms)
    [ RUN      ] ModuleTest.FCLEX
    Unsupported!
    1 	fnclex
    767
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2433): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCLEX (15 ms)
    [ RUN      ] ModuleTest.FCMOVB
    Unsupported!
    0 	fcmovb	%st(1), %st(0)
    393
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2438): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVB (16 ms)
    [ RUN      ] ModuleTest.FCMOVBE
    Unsupported!
    0 	fcmovbe	%st(1), %st(0)
    389
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2443): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVBE (0 ms)
    [ RUN      ] ModuleTest.FCMOVE
    Unsupported!
    0 	fcmove	%st(1), %st(0)
    403
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2448): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVE (15 ms)
    [ RUN      ] ModuleTest.FCMOVNB
    Unsupported!
    0 	fcmovnb	%st(1), %st(0)
    435
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2453): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVNB (0 ms)
    [ RUN      ] ModuleTest.FCMOVNBE
    Unsupported!
    0 	fcmovnbe	%st(1), %st(0)
    431
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2458): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVNBE (16 ms)
    [ RUN      ] ModuleTest.FCMOVNE
    Unsupported!
    0 	fcmovne	%st(1), %st(0)
    445
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2463): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVNE (0 ms)
    [ RUN      ] ModuleTest.FCMOVNU
    Unsupported!
    0 	fcmovnu	%st(1), %st(0)
    461
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2468): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVNU (16 ms)
    [ RUN      ] ModuleTest.FCMOVU
    Unsupported!
    0 	fcmovu	 %st(1), %st(0)
    483
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2473): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCMOVU (15 ms)
    [ RUN      ] ModuleTest.FCOM
    Unsupported!
    0 	fcom	%st(1)
    578
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2478): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOM (16 ms)
    [ RUN      ] ModuleTest.FCOMIP_STFr
    Unsupported!
    0 	fcompi
    576
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2483): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMIP_STFr (0 ms)
    [ RUN      ] ModuleTest.FCOMI_STFr
    Unsupported!
    0 	fcomi
    577
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2488): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMI_STFr (15 ms)
    [ RUN      ] ModuleTest.FCOMP
    Unsupported!
    0 	fcomp	%st(1)
    575
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2493): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMP (0 ms)
    [ RUN      ] ModuleTest.FCOMPP
    Unsupported!
    0 	fcompp
    751
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2498): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMPP (16 ms)
    [ RUN      ] ModuleTest.FCOMP_F32m
    Unsupported!
    6 	fcomps	(%edi)
    749
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2503): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMP_F32m (16 ms)
    [ RUN      ] ModuleTest.FCOMP_F64m
    Unsupported!
    6 	fcompl	(%edi)
    750
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2508): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMP_F64m (0 ms)
    [ RUN      ] ModuleTest.FCOMP_STFr
    Unsupported!
    0 	fcomp	%st(2)
    575
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2513): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOMP_STFr (15 ms)
    [ RUN      ] ModuleTest.FCOM_F32m
    Unsupported!
    6 	fcoms	(%edi)
    747
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2518): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOM_F32m (16 ms)
    [ RUN      ] ModuleTest.FCOM_F64m
    Unsupported!
    6 	fcoml	(%edi)
    748
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2523): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOM_F64m (0 ms)
    [ RUN      ] ModuleTest.FCOM_STFr
    Unsupported!
    0 	fcom	%st(2)
    578
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2528): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOM_STFr (15 ms)
    [ RUN      ] ModuleTest.FCOS
    Unsupported!
    0 	fcos
    579
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2533): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FCOS (16 ms)
    [ RUN      ] ModuleTest.FDECSTP
    Unsupported!
    0 	fdecstp
    752
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2538): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FDECSTP (0 ms)
    [ RUN      ] ModuleTest.FDIVP
    [       OK ] ModuleTest.FDIVP (109 ms)
    [ RUN      ] ModuleTest.FDIVRP
    [       OK ] ModuleTest.FDIVRP (78 ms)
    [ RUN      ] ModuleTest.FDIVR_F32m
    [       OK ] ModuleTest.FDIVR_F32m (94 ms)
    [ RUN      ] ModuleTest.FDIVR_F64m
    [       OK ] ModuleTest.FDIVR_F64m (93 ms)
    [ RUN      ] ModuleTest.FDIVR_FrST0
    [       OK ] ModuleTest.FDIVR_FrST0 (94 ms)
    [ RUN      ] ModuleTest.FDIVR_PFrST0
    [       OK ] ModuleTest.FDIVR_PFrST0 (78 ms)
    [ RUN      ] ModuleTest.FDIVR_ST0Fr
    [       OK ] ModuleTest.FDIVR_ST0Fr (94 ms)
    [ RUN      ] ModuleTest.FFREE
    Unsupported!
    0 	ffree	%st(0)
    754
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2578): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FFREE (15 ms)
    [ RUN      ] ModuleTest.FIADDm16
    [       OK ] ModuleTest.FIADDm16 (78 ms)
    [ RUN      ] ModuleTest.FIADDm32
    [       OK ] ModuleTest.FIADDm32 (94 ms)
    [ RUN      ] ModuleTest.FICOMP_16m
    Unsupported!
    9 	ficomps	(%edi)
    757
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2593): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FICOMP_16m (15 ms)
    [ RUN      ] ModuleTest.FICOMP_32m
    Unsupported!
    a 	ficompl	(%edi)
    758
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2598): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FICOMP_32m (0 ms)
    [ RUN      ] ModuleTest.FICOM_16m
    Unsupported!
    9 	ficoms	(%edi)
    755
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2603): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FICOM_16m (16 ms)
    [ RUN      ] ModuleTest.FICOM_32m
    Unsupported!
    a 	ficoml	(%edi)
    756
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2608): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FICOM_32m (16 ms)
    [ RUN      ] ModuleTest.FIDIVR_32m
    [       OK ] ModuleTest.FIDIVR_32m (78 ms)
    [ RUN      ] ModuleTest.FIDIVR_64m
    [       OK ] ModuleTest.FIDIVR_64m (78 ms)
    [ RUN      ] ModuleTest.FIDIV_32m
    [       OK ] ModuleTest.FIDIV_32m (78 ms)
    [ RUN      ] ModuleTest.FIDIV_64m
    [       OK ] ModuleTest.FIDIV_64m (93 ms)
    [ RUN      ] ModuleTest.FILD_16m
    [       OK ] ModuleTest.FILD_16m (78 ms)
    [ RUN      ] ModuleTest.FILD_32m
    [       OK ] ModuleTest.FILD_32m (78 ms)
    [ RUN      ] ModuleTest.FILD_64m
    [       OK ] ModuleTest.FILD_64m (63 ms)
    [ RUN      ] ModuleTest.FIMUL_m16
    [       OK ] ModuleTest.FIMUL_m16 (93 ms)
    [ RUN      ] ModuleTest.FIMUL_m32
    [       OK ] ModuleTest.FIMUL_m32 (78 ms)
    [ RUN      ] ModuleTest.FINCSTP
    Unsupported!
    0 	fincstp
    759
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2658): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FINCSTP (16 ms)
    [ RUN      ] ModuleTest.FINIT
    Unsupported!
    1 	fninit
    768
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2663): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FINIT (0 ms)
    [ RUN      ] ModuleTest.FISTP_16m
    Unsupported!
    4 	fistps	(%edi)
    939
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2668): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FISTP_16m (15 ms)
    [ RUN      ] ModuleTest.FISTP_32m
    Unsupported!
    4 	fistpl	(%edi)
    940
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2673): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FISTP_32m (16 ms)
    [ RUN      ] ModuleTest.FISTP_64m
    Unsupported!
    4 	fistpll	(%edi)
    941
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2678): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FISTP_64m (0 ms)
    [ RUN      ] ModuleTest.FISTTP_16m
    Unsupported!
    4 	fisttps	(%edi)
    925
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2683): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FISTTP_16m (16 ms)
    [ RUN      ] ModuleTest.FISTTP_32m
    Unsupported!
    4 	fisttpl	(%edi)
    926
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2688): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FISTTP_32m (0 ms)
    [ RUN      ] ModuleTest.FISTTP_64m
    Unsupported!
    4 	fisttpll	(%edi)
    927
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2693): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FISTTP_64m (15 ms)
    [ RUN      ] ModuleTest.FIST_16m
    Unsupported!
    4 	fists	(%edi)
    937
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2698): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FIST_16m (0 ms)
    [ RUN      ] ModuleTest.FIST_32m
    Unsupported!
    4 	fistl	(%edi)
    938
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2703): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FIST_32m (16 ms)
    [ RUN      ] ModuleTest.FISUBRm16
    [       OK ] ModuleTest.FISUBRm16 (78 ms)
    [ RUN      ] ModuleTest.FISUBRm32
    [       OK ] ModuleTest.FISUBRm32 (93 ms)
    [ RUN      ] ModuleTest.FISUBm16
    [       OK ] ModuleTest.FISUBm16 (78 ms)
    [ RUN      ] ModuleTest.FISUBm32
    [       OK ] ModuleTest.FISUBm32 (78 ms)
    [ RUN      ] ModuleTest.FLD1
    [       OK ] ModuleTest.FLD1 (78 ms)
    [ RUN      ] ModuleTest.FLDCW
    Unsupported!
    d 	fldcw	(%edi)
    760
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2733): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDCW (16 ms)
    [ RUN      ] ModuleTest.FLDENV
    Unsupported!
    7 	fldenv	(%edi)
    761
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2738): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDENV (0 ms)
    [ RUN      ] ModuleTest.FLDL2E
    Unsupported!
    0 	fldl2e
    762
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2743): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDL2E (16 ms)
    [ RUN      ] ModuleTest.FLDL2T
    Unsupported!
    0 	fldl2t
    763
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2748): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDL2T (0 ms)
    [ RUN      ] ModuleTest.FLDLG2
    Unsupported!
    0 	fldlg2
    764
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2753): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDLG2 (15 ms)
    [ RUN      ] ModuleTest.FLDLN2
    Unsupported!
    0 	fldln2
    765
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2758): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDLN2 (16 ms)
    [ RUN      ] ModuleTest.FLDPI
    Unsupported!
    0 	fldpi
    766
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2763): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FLDPI (0 ms)
    [ RUN      ] ModuleTest.FLDZ
    [       OK ] ModuleTest.FLDZ (78 ms)
    [ RUN      ] ModuleTest.FMULP
    [       OK ] ModuleTest.FMULP (93 ms)
    [ RUN      ] ModuleTest.FMULP_rST0
    [       OK ] ModuleTest.FMULP_rST0 (78 ms)
    [ RUN      ] ModuleTest.FNCLEX
    Unsupported!
    0 	fnclex
    767
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2783): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FNCLEX (0 ms)
    [ RUN      ] ModuleTest.FNINIT
    Unsupported!
    0 	fninit
    768
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2788): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FNINIT (16 ms)
    [ RUN      ] ModuleTest.FNOP
    Unsupported!
    0 	fnop
    769
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2793): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FNOP (0 ms)
    [ RUN      ] ModuleTest.FNSAVE
    Unsupported!
    7 	fnsave	(%edi)
    788
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2798): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FNSAVE (16 ms)
    [ RUN      ] ModuleTest.FNSTCW
    [       OK ] ModuleTest.FNSTCW (78 ms)
    [ RUN      ] ModuleTest.FNSTENVm
    [       OK ] ModuleTest.FNSTENVm (93 ms)
    [ RUN      ] ModuleTest.FNSTSWa
    Unsupported!
    5 	fnstsw
    771
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2813): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FNSTSWa (0 ms)
    [ RUN      ] ModuleTest.FNSTSWm
    Unsupported!
    a 	fnstsw	(%edi)
    772
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2818): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FNSTSWm (16 ms)
    [ RUN      ] ModuleTest.FPATAN
    Unsupported!
    b 	fpatan
    782
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2823): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FPATAN (0 ms)
    [ RUN      ] ModuleTest.FPREM
    Unsupported!
    12 	fprem
    783
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2828): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FPREM (15 ms)
    [ RUN      ] ModuleTest.FPREM1
    Unsupported!
    12 	fprem1
    784
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2833): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FPREM1 (16 ms)
    [ RUN      ] ModuleTest.FRNDINT
    Unsupported!
    0 	frndint
    786
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2838): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FRNDINT (0 ms)
    [ RUN      ] ModuleTest.FRSTOR
    Unsupported!
    7 	fnsave	(%edi)
    788
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2843): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FRSTOR (16 ms)
    [ RUN      ] ModuleTest.FSAVE
    Unsupported!
    8 	fnsave	(%edi)
    788
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2848): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FSAVE (15 ms)
    [ RUN      ] ModuleTest.FSCALE
    Unsupported!
    0 	fscale
    789
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2853): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FSCALE (0 ms)
    [ RUN      ] ModuleTest.FSIN
    [       OK ] ModuleTest.FSIN (78 ms)
    [ RUN      ] ModuleTest.FSINCOS
    Unsupported!
    0 	fsincos
    790
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2863): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FSINCOS (16 ms)
    [ RUN      ] ModuleTest.FSQRT
    Unsupported!
    10 	fsqrt
    2527
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2868): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FSQRT (15 ms)
    [ RUN      ] ModuleTest.FSTCW
    [       OK ] ModuleTest.FSTCW (63 ms)
    [ RUN      ] ModuleTest.FSTENVm
    [       OK ] ModuleTest.FSTENVm (93 ms)
    [ RUN      ] ModuleTest.FSTSWa
    Unsupported!
    6 	fnstsw
    771
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2883): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FSTSWa (16 ms)
    [ RUN      ] ModuleTest.FSTSWm
    Unsupported!
    b 	fnstsw	(%edi)
    772
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2888): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FSTSWm (0 ms)
    [ RUN      ] ModuleTest.FSUBP
    [       OK ] ModuleTest.FSUBP (94 ms)
    [ RUN      ] ModuleTest.FSUBP_rST0
    [       OK ] ModuleTest.FSUBP_rST0 (78 ms)
    [ RUN      ] ModuleTest.FSUBRP
    [       OK ] ModuleTest.FSUBRP (93 ms)
    [ RUN      ] ModuleTest.FSUBRP_rST0
    [       OK ] ModuleTest.FSUBRP_rST0 (78 ms)
    [ RUN      ] ModuleTest.FTST
    Unsupported!
    0 	ftst
    2695
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2913): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FTST (16 ms)
    [ RUN      ] ModuleTest.FUCOM
    Unsupported!
    0 	fucom
    2719
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2918): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOM (15 ms)
    [ RUN      ] ModuleTest.FUCOMIP_STFr
    Unsupported!
    0 	fucompi
    2709
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2923): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOMIP_STFr (0 ms)
    [ RUN      ] ModuleTest.FUCOMI_STFr
    Unsupported!
    0 	fucomi
    2710
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2928): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOMI_STFr (16 ms)
    [ RUN      ] ModuleTest.FUCOMP
    Unsupported!
    0 	fucomp
    2712
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2933): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOMP (0 ms)
    [ RUN      ] ModuleTest.FUCOMPP
    Unsupported!
    0 	fucompp
    2711
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2938): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOMPP (16 ms)
    [ RUN      ] ModuleTest.FUCOMP_STFr
    Unsupported!
    0 	fucomp	%st(2)
    2712
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2943): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOMP_STFr (0 ms)
    [ RUN      ] ModuleTest.FUCOM_STFr
    Unsupported!
    0 	fucom	%st(2)
    2719
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2948): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FUCOM_STFr (15 ms)
    [ RUN      ] ModuleTest.FXAM
    Unsupported!
    0 	fxam
    793
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2953): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FXAM (16 ms)
    [ RUN      ] ModuleTest.FXCH
    Unsupported!
    0 	fxch
    4471
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2958): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FXCH (0 ms)
    [ RUN      ] ModuleTest.FXCH_STFr
    Unsupported!
    0 	fxch	%st(2)
    4471
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2963): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FXCH_STFr (15 ms)
    [ RUN      ] ModuleTest.FXRSTOR
    Unsupported!
    a 	fxsave	(%edi)
    796
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2968): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FXRSTOR (0 ms)
    [ RUN      ] ModuleTest.FXSAVE
    Unsupported!
    a 	fxsave	(%edi)
    796
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2973): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FXSAVE (16 ms)
    [ RUN      ] ModuleTest.FXTRACT
    Unsupported!
    0 	fxtract
    798
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2978): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FXTRACT (0 ms)
    [ RUN      ] ModuleTest.FYL2X
    Unsupported!
    d 	fyl2x
    799
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2983): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FYL2X (16 ms)
    [ RUN      ] ModuleTest.FYL2XP1
    Unsupported!
    0 	fyl2xp1
    800
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(2988): error: Value of: testFn != NULL
      Actual: false
    Expected: true
    [  FAILED  ] ModuleTest.FYL2XP1 (15 ms)
    [ RUN      ] ModuleTest.IDIV16r
    [       OK ] ModuleTest.IDIV16r (94 ms)
    [ RUN      ] ModuleTest.IDIV32r
    [       OK ] ModuleTest.IDIV32r (78 ms)
    [ RUN      ] ModuleTest.IDIV8r
    [       OK ] ModuleTest.IDIV8r (62 ms)
    [ RUN      ] ModuleTest.ILD_F16m
    [       OK ] ModuleTest.ILD_F16m (78 ms)
    [ RUN      ] ModuleTest.ILD_F32m
    [       OK ] ModuleTest.ILD_F32m (94 ms)
    [ RUN      ] ModuleTest.ILD_F64m
    [       OK ] ModuleTest.ILD_F64m (78 ms)
    [ RUN      ] ModuleTest.IMUL16r
    [       OK ] ModuleTest.IMUL16r (62 ms)
    [ RUN      ] ModuleTest.IMUL16rr
    [       OK ] ModuleTest.IMUL16rr (78 ms)
    [ RUN      ] ModuleTest.IMUL16rri
    [       OK ] ModuleTest.IMUL16rri (63 ms)
    [ RUN      ] ModuleTest.IMUL32r
    [       OK ] ModuleTest.IMUL32r (78 ms)
    [ RUN      ] ModuleTest.IMUL32rr
    [       OK ] ModuleTest.IMUL32rr (62 ms)
    [ RUN      ] ModuleTest.IMUL32rri
    [       OK ] ModuleTest.IMUL32rri (62 ms)
    [ RUN      ] ModuleTest.IMUL8r
    [       OK ] ModuleTest.IMUL8r (78 ms)
    [ RUN      ] ModuleTest.INC16r
    [       OK ] ModuleTest.INC16r (63 ms)
    [ RUN      ] ModuleTest.INC32r
    [       OK ] ModuleTest.INC32r (78 ms)
    [ RUN      ] ModuleTest.INC8r
    [       OK ] ModuleTest.INC8r (62 ms)
    [ RUN      ] ModuleTest.LAHF
    [       OK ] ModuleTest.LAHF (78 ms)
    [ RUN      ] ModuleTest.LD_F0
    [       OK ] ModuleTest.LD_F0 (63 ms)
    [ RUN      ] ModuleTest.LD_F1
    [       OK ] ModuleTest.LD_F1 (78 ms)
    [ RUN      ] ModuleTest.LD_F32m
    [       OK ] ModuleTest.LD_F32m (78 ms)
    [ RUN      ] ModuleTest.LD_F80m
    [       OK ] ModuleTest.LD_F80m (78 ms)
    [ RUN      ] ModuleTest.LD_Frr
    [       OK ] ModuleTest.LD_Frr (78 ms)
    [ RUN      ] ModuleTest.LEA16r
    [       OK ] ModuleTest.LEA16r (62 ms)
    [ RUN      ] ModuleTest.LEA32r
    [       OK ] ModuleTest.LEA32r (62 ms)
    [ RUN      ] ModuleTest.LEAVE
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(1561): error: Value of: in->ESP
      Actual: 88973312
    Expected: out->ESP
    Which is: 88973292
    ..\..\..\..\mc-sema\validator\testSemantics\testSemantics.auto.cpp(1562): error: Value of: in->EBP
      Actual: 0
    Expected: out->EBP
    Which is: 88973572
    [  FAILED  ] ModuleTest.LEAVE (63 ms)
    [ RUN      ] ModuleTest.LOOP
    [       OK ] ModuleTest.LOOP (78 ms)
    [ RUN      ] ModuleTest.LOOPNE
    [       OK ] ModuleTest.LOOPNE (62 ms)
    [ RUN      ] ModuleTest.Lea32R1
    [       OK ] ModuleTest.Lea32R1 (78 ms)
    [ RUN      ] ModuleTest.Lea32R2
    [       OK ] ModuleTest.Lea32R2 (63 ms)
    [ RUN      ] ModuleTest.MOV16ri
    [       OK ] ModuleTest.MOV16ri (62 ms)
    [ RUN      ] ModuleTest.MOV16rr
    [       OK ] ModuleTest.MOV16rr (78 ms)
    [ RUN      ] ModuleTest.MOV32ri
    [       OK ] ModuleTest.MOV32ri (62 ms)
    [ RUN      ] ModuleTest.MOV32rr
    [       OK ] ModuleTest.MOV32rr (63 ms)
    [ RUN      ] ModuleTest.MOV8ri
    [       OK ] ModuleTest.MOV8ri (62 ms)
    [ RUN      ] ModuleTest.MOV8rr
    [       OK ] ModuleTest.MOV8rr (78 ms)
    [ RUN      ] ModuleTest.MOVSX16rr8
    [       OK ] ModuleTest.MOVSX16rr8 (62 ms)
    [ RUN      ] ModuleTest.MOVSX32rr16
    [       OK ] ModuleTest.MOVSX32rr16 (63 ms)
    [ RUN      ] ModuleTest.MOVSX32rr8
    [       OK ] ModuleTest.MOVSX32rr8 (62 ms)
    [ RUN      ] ModuleTest.MOVZX16rr8
    [       OK ] ModuleTest.MOVZX16rr8 (78 ms)
    [ RUN      ] ModuleTest.MOVZX32rr16
    [       OK ] ModuleTest.MOVZX32rr16 (63 ms)
    [ RUN      ] ModuleTest.MOVZX32rr8
    [       OK ] ModuleTest.MOVZX32rr8 (62 ms)
    [ RUN      ] ModuleTest.MUL_F32m
    [       OK ] ModuleTest.MUL_F32m (94 ms)
    [ RUN      ] ModuleTest.MUL_F64m
    [       OK ] ModuleTest.MUL_F64m (93 ms)
    [ RUN      ] ModuleTest.MUL_FST0r
    [       OK ] ModuleTest.MUL_FST0r (94 ms)
    [ RUN      ] ModuleTest.MUL_FrST0
    [       OK ] ModuleTest.MUL_FrST0 (78 ms)
    [ RUN      ] ModuleTest.NEG16r
    [       OK ] ModuleTest.NEG16r (62 ms)
    [ RUN      ] ModuleTest.NEG32r
    [       OK ] ModuleTest.NEG32r (78 ms)
    [ RUN      ] ModuleTest.NEG8r
    [       OK ] ModuleTest.NEG8r (63 ms)
    [ RUN      ] ModuleTest.NOOP
    [       OK ] ModuleTest.NOOP (62 ms)
    [ RUN      ] ModuleTest.NOT16r
    [       OK ] ModuleTest.NOT16r (78 ms)
    [ RUN      ] ModuleTest.NOT32r
    [       OK ] ModuleTest.NOT32r (62 ms)
    [ RUN      ] ModuleTest.NOT8r
    [       OK ] ModuleTest.NOT8r (63 ms)
    [ RUN      ] ModuleTest.OR16i16
    [       OK ] ModuleTest.OR16i16 (78 ms)
    [ RUN      ] ModuleTest.OR16ri
    [       OK ] ModuleTest.OR16ri (62 ms)
    [ RUN      ] ModuleTest.OR16rm
    [       OK ] ModuleTest.OR16rm (63 ms)
    [ RUN      ] ModuleTest.OR16rr
    [       OK ] ModuleTest.OR16rr (78 ms)
    [ RUN      ] ModuleTest.OR32i32
    [       OK ] ModuleTest.OR32i32 (62 ms)
    [ RUN      ] ModuleTest.OR32mi
    [       OK ] ModuleTest.OR32mi (62 ms)
    [ RUN      ] ModuleTest.OR32mr
    [       OK ] ModuleTest.OR32mr (78 ms)
    [ RUN      ] ModuleTest.OR32ri
    [       OK ] ModuleTest.OR32ri (63 ms)
    [ RUN      ] ModuleTest.OR32rr
    [       OK ] ModuleTest.OR32rr (62 ms)
    [ RUN      ] ModuleTest.OR8i8
    [       OK ] ModuleTest.OR8i8 (78 ms)
    [ RUN      ] ModuleTest.OR8ri
    [       OK ] ModuleTest.OR8ri (63 ms)
    [ RUN      ] ModuleTest.OR8rr
    [       OK ] ModuleTest.OR8rr (62 ms)
    [ RUN      ] ModuleTest.POP16r
    [       OK ] ModuleTest.POP16r (78 ms)
    [ RUN      ] ModuleTest.POP32r
    [       OK ] ModuleTest.POP32r (62 ms)
    [ RUN      ] ModuleTest.PUSH16r
    [       OK ] ModuleTest.PUSH16r (63 ms)
    [ RUN      ] ModuleTest.PUSH32r
    [       OK ] ModuleTest.PUSH32r (78 ms)
    [ RUN      ] ModuleTest.PUSHi16
    [       OK ] ModuleTest.PUSHi16 (62 ms)
    [ RUN      ] ModuleTest.PUSHi32
    [       OK ] ModuleTest.PUSHi32 (63 ms)
    [ RUN      ] ModuleTest.PUSHi8
    [       OK ] ModuleTest.PUSHi8 (62 ms)
    [ RUN      ] ModuleTest.PushPopR
    [       OK ] ModuleTest.PushPopR (78 ms)
    [ RUN      ] ModuleTest.Pushl32m
    [       OK ] ModuleTest.Pushl32m (62 ms)
    [ RUN      ] ModuleTest.RCL16r1
    [       OK ] ModuleTest.RCL16r1 (78 ms)
    [ RUN      ] ModuleTest.RCL16rCL
    [       OK ] ModuleTest.RCL16rCL (63 ms)
    [ RUN      ] ModuleTest.RCL16ri
    [       OK ] ModuleTest.RCL16ri (78 ms)
    [ RUN      ] ModuleTest.RCL32r1
    [       OK ] ModuleTest.RCL32r1 (62 ms)
    [ RUN      ] ModuleTest.RCL32rCL
    [       OK ] ModuleTest.RCL32rCL (63 ms)
    [ RUN      ] ModuleTest.RCL32ri
    [       OK ] ModuleTest.RCL32ri (78 ms)
    [ RUN      ] ModuleTest.RCL8r1
    [       OK ] ModuleTest.RCL8r1 (62 ms)
    [ RUN      ] ModuleTest.RCL8rCL
    [       OK ] ModuleTest.RCL8rCL (62 ms)
    [ RUN      ] ModuleTest.RCL8ri
    [       OK ] ModuleTest.RCL8ri (78 ms)
    [ RUN      ] ModuleTest.RCR16r1
    [       OK ] ModuleTest.RCR16r1 (63 ms)
    [ RUN      ] ModuleTest.RCR16rCL
    [       OK ] ModuleTest.RCR16rCL (78 ms)
    [ RUN      ] ModuleTest.RCR16ri
    [       OK ] ModuleTest.RCR16ri (62 ms)
    [ RUN      ] ModuleTest.RCR32r1
    [       OK ] ModuleTest.RCR32r1 (63 ms)
    [ RUN      ] ModuleTest.RCR32rCL
    [       OK ] ModuleTest.RCR32rCL (78 ms)
    [ RUN      ] ModuleTest.RCR32ri
    [       OK ] ModuleTest.RCR32ri (62 ms)
    [ RUN      ] ModuleTest.RCR8r1
    [       OK ] ModuleTest.RCR8r1 (78 ms)
    [ RUN      ] ModuleTest.RCR8rCL
    [       OK ] ModuleTest.RCR8rCL (62 ms)
    [ RUN      ] ModuleTest.RCR8ri
    [       OK ] ModuleTest.RCR8ri (78 ms)
    [ RUN      ] ModuleTest.ROL16r1
    [       OK ] ModuleTest.ROL16r1 (63 ms)
    [ RUN      ] ModuleTest.ROL16rCL
    [       OK ] ModuleTest.ROL16rCL (78 ms)
    [ RUN      ] ModuleTest.ROL16ri
    [       OK ] ModuleTest.ROL16ri (78 ms)
    [ RUN      ] ModuleTest.ROL32r1
    [       OK ] ModuleTest.ROL32r1 (62 ms)
    [ RUN      ] ModuleTest.ROL32rCL
    [       OK ] ModuleTest.ROL32rCL (78 ms)
    [ RUN      ] ModuleTest.ROL32ri
    [       OK ] ModuleTest.ROL32ri (63 ms)
    [ RUN      ] ModuleTest.ROL8r1
    [       OK ] ModuleTest.ROL8r1 (62 ms)
    [ RUN      ] ModuleTest.ROL8rCL
    [       OK ] ModuleTest.ROL8rCL (78 ms)
    [ RUN      ] ModuleTest.ROL8ri
    [       OK ] ModuleTest.ROL8ri (62 ms)
    [ RUN      ] ModuleTest.ROR16r1
    [       OK ] ModuleTest.ROR16r1 (78 ms)
    [ RUN      ] ModuleTest.ROR16rCL
    [       OK ] ModuleTest.ROR16rCL (63 ms)
    [ RUN      ] ModuleTest.ROR16ri
    [       OK ] ModuleTest.ROR16ri (62 ms)
    [ RUN      ] ModuleTest.ROR32r1
    [       OK ] ModuleTest.ROR32r1 (63 ms)
    [ RUN      ] ModuleTest.ROR32rCL
    [       OK ] ModuleTest.ROR32rCL (78 ms)
    [ RUN      ] ModuleTest.ROR32ri
    [       OK ] ModuleTest.ROR32ri (62 ms)
    [ RUN      ] ModuleTest.ROR8r1
    [       OK ] ModuleTest.ROR8r1 (78 ms)
    [ RUN      ] ModuleTest.ROR8rCL
    [       OK ] ModuleTest.ROR8rCL (62 ms)
    [ RUN      ] ModuleTest.ROR8ri
    [       OK ] ModuleTest.ROR8ri (63 ms)
    [ RUN      ] ModuleTest.SBB16i16
    [       OK ] ModuleTest.SBB16i16 (78 ms)
    [ RUN      ] ModuleTest.SBB16ri
    [       OK ] ModuleTest.SBB16ri (62 ms)
    [ RUN      ] ModuleTest.SBB16rr
    [       OK ] ModuleTest.SBB16rr (94 ms)
    [ RUN      ] ModuleTest.SBB32i32
    [       OK ] ModuleTest.SBB32i32 (62 ms)
    [ RUN      ] ModuleTest.SBB32mr
    [       OK ] ModuleTest.SBB32mr (78 ms)
    [ RUN      ] ModuleTest.SBB32ri
    [       OK ] ModuleTest.SBB32ri (78 ms)
    [ RUN      ] ModuleTest.SBB32rm
    [       OK ] ModuleTest.SBB32rm (63 ms)
    [ RUN      ] ModuleTest.SBB32rr
    [       OK ] ModuleTest.SBB32rr (78 ms)
    [ RUN      ] ModuleTest.SBB8i8
    [       OK ] ModuleTest.SBB8i8 (62 ms)
    [ RUN      ] ModuleTest.SBB8ri
    [       OK ] ModuleTest.SBB8ri (62 ms)
    [ RUN      ] ModuleTest.SBB8rr
    [       OK ] ModuleTest.SBB8rr (78 ms)
    [ RUN      ] ModuleTest.SETNEm
    [       OK ] ModuleTest.SETNEm (63 ms)
    [ RUN      ] ModuleTest.SETNEr
    [       OK ] ModuleTest.SETNEr (62 ms)
    [ RUN      ] ModuleTest.SHL16r1
    [       OK ] ModuleTest.SHL16r1 (78 ms)
    [ RUN      ] ModuleTest.SHL16rCL
    [       OK ] ModuleTest.SHL16rCL (62 ms)
    [ RUN      ] ModuleTest.SHL16ri
    [       OK ] ModuleTest.SHL16ri (78 ms)
    [ RUN      ] ModuleTest.SHL32r1
    [       OK ] ModuleTest.SHL32r1 (63 ms)
    [ RUN      ] ModuleTest.SHL32rCL
    [       OK ] ModuleTest.SHL32rCL (78 ms)
    [ RUN      ] ModuleTest.SHL32ri
    [       OK ] ModuleTest.SHL32ri (62 ms)
    [ RUN      ] ModuleTest.SHL8r1
    [       OK ] ModuleTest.SHL8r1 (78 ms)
    [ RUN      ] ModuleTest.SHL8rCL
    [       OK ] ModuleTest.SHL8rCL (63 ms)
    [ RUN      ] ModuleTest.SHL8ri
    [       OK ] ModuleTest.SHL8ri (78 ms)
    [ RUN      ] ModuleTest.SHR16r1
    [       OK ] ModuleTest.SHR16r1 (62 ms)
    [ RUN      ] ModuleTest.SHR16rCL
    [       OK ] ModuleTest.SHR16rCL (78 ms)
    [ RUN      ] ModuleTest.SHR16ri
    [       OK ] ModuleTest.SHR16ri (62 ms)
    [ RUN      ] ModuleTest.SHR32r1
    [       OK ] ModuleTest.SHR32r1 (78 ms)
    [ RUN      ] ModuleTest.SHR32rCL
    [       OK ] ModuleTest.SHR32rCL (110 ms)
    [ RUN      ] ModuleTest.SHR32ri
    [       OK ] ModuleTest.SHR32ri (78 ms)
    [ RUN      ] ModuleTest.SHR8r1
    [       OK ] ModuleTest.SHR8r1 (78 ms)
    [ RUN      ] ModuleTest.SHR8rCL
    [       OK ] ModuleTest.SHR8rCL (62 ms)
    [ RUN      ] ModuleTest.SHR8ri
    [       OK ] ModuleTest.SHR8ri (62 ms)
    [ RUN      ] ModuleTest.SHRD32rri8
    [       OK ] ModuleTest.SHRD32rri8 (78 ms)
    [ RUN      ] ModuleTest.STC
    [       OK ] ModuleTest.STC (63 ms)
    [ RUN      ] ModuleTest.STD
    [       OK ] ModuleTest.STD (78 ms)
    [ RUN      ] ModuleTest.ST_F32m
    [       OK ] ModuleTest.ST_F32m (78 ms)
    [ RUN      ] ModuleTest.ST_F64m
    [       OK ] ModuleTest.ST_F64m (78 ms)
    [ RUN      ] ModuleTest.ST_Frr
    [       OK ] ModuleTest.ST_Frr (78 ms)
    [ RUN      ] ModuleTest.ST_PF32m
    [       OK ] ModuleTest.ST_PF32m (78 ms)
    [ RUN      ] ModuleTest.ST_PF64m
    [       OK ] ModuleTest.ST_PF64m (62 ms)
    [ RUN      ] ModuleTest.ST_PF80m
    [       OK ] ModuleTest.ST_PF80m (78 ms)
    [ RUN      ] ModuleTest.ST_PFr
    [       OK ] ModuleTest.ST_PFr (78 ms)
    [ RUN      ] ModuleTest.SUB16i16
    [       OK ] ModuleTest.SUB16i16 (78 ms)
    [ RUN      ] ModuleTest.SUB16mr
    [       OK ] ModuleTest.SUB16mr (78 ms)
    [ RUN      ] ModuleTest.SUB16ri
    [       OK ] ModuleTest.SUB16ri (63 ms)
    [ RUN      ] ModuleTest.SUB16rm
    [       OK ] ModuleTest.SUB16rm (78 ms)
    [ RUN      ] ModuleTest.SUB32i32
    [       OK ] ModuleTest.SUB32i32 (62 ms)
    [ RUN      ] ModuleTest.SUB32ri
    [       OK ] ModuleTest.SUB32ri (62 ms)
    [ RUN      ] ModuleTest.SUB32rr
    [       OK ] ModuleTest.SUB32rr (78 ms)
    [ RUN      ] ModuleTest.SUB8i8
    [       OK ] ModuleTest.SUB8i8 (63 ms)
    [ RUN      ] ModuleTest.SUB8mr
    [       OK ] ModuleTest.SUB8mr (78 ms)
    [ RUN      ] ModuleTest.SUB8ri
    [       OK ] ModuleTest.SUB8ri (62 ms)
    [ RUN      ] ModuleTest.SUB8rm
    [       OK ] ModuleTest.SUB8rm (78 ms)
    [ RUN      ] ModuleTest.SUBR_F32m
    [       OK ] ModuleTest.SUBR_F32m (94 ms)
    [ RUN      ] ModuleTest.SUBR_F64m
    [       OK ] ModuleTest.SUBR_F64m (78 ms)
    [ RUN      ] ModuleTest.SUBR_FST0r
    [       OK ] ModuleTest.SUBR_FST0r (78 ms)
    [ RUN      ] ModuleTest.SUBR_FrST0
    [       OK ] ModuleTest.SUBR_FrST0 (109 ms)
    [ RUN      ] ModuleTest.SUB_F32m
    [       OK ] ModuleTest.SUB_F32m (94 ms)
    [ RUN      ] ModuleTest.SUB_F64m
    [       OK ] ModuleTest.SUB_F64m (78 ms)
    [ RUN      ] ModuleTest.SUB_FST0r
    [       OK ] ModuleTest.SUB_FST0r (93 ms)
    [ RUN      ] ModuleTest.SUB_FrST0
    [       OK ] ModuleTest.SUB_FrST0 (78 ms)
    [ RUN      ] ModuleTest.Sar32RI1
    [       OK ] ModuleTest.Sar32RI1 (78 ms)
    [ RUN      ] ModuleTest.Sar32RI2
    [       OK ] ModuleTest.Sar32RI2 (63 ms)
    [ RUN      ] ModuleTest.Sbb32RR1
    [       OK ] ModuleTest.Sbb32RR1 (78 ms)
    [ RUN      ] ModuleTest.Sbb32RR2
    [       OK ] ModuleTest.Sbb32RR2 (62 ms)
    [ RUN      ] ModuleTest.TEST16i16
    [       OK ] ModuleTest.TEST16i16 (62 ms)
    [ RUN      ] ModuleTest.TEST16ri
    [       OK ] ModuleTest.TEST16ri (78 ms)
    [ RUN      ] ModuleTest.TEST16rr
    [       OK ] ModuleTest.TEST16rr (63 ms)
    [ RUN      ] ModuleTest.TEST32i32
    [       OK ] ModuleTest.TEST32i32 (62 ms)
    [ RUN      ] ModuleTest.TEST32ri
    [       OK ] ModuleTest.TEST32ri (78 ms)
    [ RUN      ] ModuleTest.TEST32rr
    [       OK ] ModuleTest.TEST32rr (63 ms)
    [ RUN      ] ModuleTest.TEST8i8
    [       OK ] ModuleTest.TEST8i8 (78 ms)
    [ RUN      ] ModuleTest.TEST8ri
    [       OK ] ModuleTest.TEST8ri (62 ms)
    [ RUN      ] ModuleTest.TEST8rr
    [       OK ] ModuleTest.TEST8rr (62 ms)
    [ RUN      ] ModuleTest.Test32RR1
    [       OK ] ModuleTest.Test32RR1 (63 ms)
    [ RUN      ] ModuleTest.Test32RR2
    [       OK ] ModuleTest.Test32RR2 (78 ms)
    [ RUN      ] ModuleTest.XADD16rr
    [       OK ] ModuleTest.XADD16rr (78 ms)
    [ RUN      ] ModuleTest.XADD32rm
    [       OK ] ModuleTest.XADD32rm (62 ms)
    [ RUN      ] ModuleTest.XADD32rr
    [       OK ] ModuleTest.XADD32rr (78 ms)
    [ RUN      ] ModuleTest.XADD8rr
    [       OK ] ModuleTest.XADD8rr (63 ms)
    [ RUN      ] ModuleTest.XCHG16ar
    [       OK ] ModuleTest.XCHG16ar (78 ms)
    [ RUN      ] ModuleTest.XCHG16rr
    [       OK ] ModuleTest.XCHG16rr (62 ms)
    [ RUN      ] ModuleTest.XCHG32ar
    [       OK ] ModuleTest.XCHG32ar (62 ms)
    [ RUN      ] ModuleTest.XCHG32rr
    [       OK ] ModuleTest.XCHG32rr (63 ms)
    [ RUN      ] ModuleTest.XCHG8rr
    [       OK ] ModuleTest.XCHG8rr (78 ms)
    [ RUN      ] ModuleTest.XOR16i16
    [       OK ] ModuleTest.XOR16i16 (62 ms)
    [ RUN      ] ModuleTest.XOR16ri
    [       OK ] ModuleTest.XOR16ri (78 ms)
    [ RUN      ] ModuleTest.XOR16rr
    [       OK ] ModuleTest.XOR16rr (78 ms)
    [ RUN      ] ModuleTest.XOR32i32
    [       OK ] ModuleTest.XOR32i32 (63 ms)
    [ RUN      ] ModuleTest.XOR32ri
    [       OK ] ModuleTest.XOR32ri (78 ms)
    [ RUN      ] ModuleTest.XOR32rr
    [       OK ] ModuleTest.XOR32rr (78 ms)
    [ RUN      ] ModuleTest.XOR8i8
    [       OK ] ModuleTest.XOR8i8 (78 ms)
    [ RUN      ] ModuleTest.XOR8ri
    [       OK ] ModuleTest.XOR8ri (62 ms)
    [ RUN      ] ModuleTest.XOR8rr
    [       OK ] ModuleTest.XOR8rr (78 ms)
    [ RUN      ] ModuleTest.StructureLayout
    [       OK ] ModuleTest.StructureLayout (16 ms)
    [----------] 426 tests from ModuleTest (28189 ms total)
    
    [----------] Global test environment tear-down
    [==========] 426 tests from 1 test case ran. (28189 ms total)
    [  PASSED  ] 341 tests.
    [  FAILED  ] 85 tests, listed below:
    [  FAILED  ] ModuleTest.ABS_F
    [  FAILED  ] ModuleTest.ENTER
    [  FAILED  ] ModuleTest.F2XM1
    [  FAILED  ] ModuleTest.FABS
    [  FAILED  ] ModuleTest.FBLD
    [  FAILED  ] ModuleTest.FBSTP
    [  FAILED  ] ModuleTest.FCHS
    [  FAILED  ] ModuleTest.FCLEX
    [  FAILED  ] ModuleTest.FCMOVB
    [  FAILED  ] ModuleTest.FCMOVBE
    [  FAILED  ] ModuleTest.FCMOVE
    [  FAILED  ] ModuleTest.FCMOVNB
    [  FAILED  ] ModuleTest.FCMOVNBE
    [  FAILED  ] ModuleTest.FCMOVNE
    [  FAILED  ] ModuleTest.FCMOVNU
    [  FAILED  ] ModuleTest.FCMOVU
    [  FAILED  ] ModuleTest.FCOM
    [  FAILED  ] ModuleTest.FCOMIP_STFr
    [  FAILED  ] ModuleTest.FCOMI_STFr
    [  FAILED  ] ModuleTest.FCOMP
    [  FAILED  ] ModuleTest.FCOMPP
    [  FAILED  ] ModuleTest.FCOMP_F32m
    [  FAILED  ] ModuleTest.FCOMP_F64m
    [  FAILED  ] ModuleTest.FCOMP_STFr
    [  FAILED  ] ModuleTest.FCOM_F32m
    [  FAILED  ] ModuleTest.FCOM_F64m
    [  FAILED  ] ModuleTest.FCOM_STFr
    [  FAILED  ] ModuleTest.FCOS
    [  FAILED  ] ModuleTest.FDECSTP
    [  FAILED  ] ModuleTest.FFREE
    [  FAILED  ] ModuleTest.FICOMP_16m
    [  FAILED  ] ModuleTest.FICOMP_32m
    [  FAILED  ] ModuleTest.FICOM_16m
    [  FAILED  ] ModuleTest.FICOM_32m
    [  FAILED  ] ModuleTest.FINCSTP
    [  FAILED  ] ModuleTest.FINIT
    [  FAILED  ] ModuleTest.FISTP_16m
    [  FAILED  ] ModuleTest.FISTP_32m
    [  FAILED  ] ModuleTest.FISTP_64m
    [  FAILED  ] ModuleTest.FISTTP_16m
    [  FAILED  ] ModuleTest.FISTTP_32m
    [  FAILED  ] ModuleTest.FISTTP_64m
    [  FAILED  ] ModuleTest.FIST_16m
    [  FAILED  ] ModuleTest.FIST_32m
    [  FAILED  ] ModuleTest.FLDCW
    [  FAILED  ] ModuleTest.FLDENV
    [  FAILED  ] ModuleTest.FLDL2E
    [  FAILED  ] ModuleTest.FLDL2T
    [  FAILED  ] ModuleTest.FLDLG2
    [  FAILED  ] ModuleTest.FLDLN2
    [  FAILED  ] ModuleTest.FLDPI
    [  FAILED  ] ModuleTest.FNCLEX
    [  FAILED  ] ModuleTest.FNINIT
    [  FAILED  ] ModuleTest.FNOP
    [  FAILED  ] ModuleTest.FNSAVE
    [  FAILED  ] ModuleTest.FNSTSWa
    [  FAILED  ] ModuleTest.FNSTSWm
    [  FAILED  ] ModuleTest.FPATAN
    [  FAILED  ] ModuleTest.FPREM
    [  FAILED  ] ModuleTest.FPREM1
    [  FAILED  ] ModuleTest.FRNDINT
    [  FAILED  ] ModuleTest.FRSTOR
    [  FAILED  ] ModuleTest.FSAVE
    [  FAILED  ] ModuleTest.FSCALE
    [  FAILED  ] ModuleTest.FSINCOS
    [  FAILED  ] ModuleTest.FSQRT
    [  FAILED  ] ModuleTest.FSTSWa
    [  FAILED  ] ModuleTest.FSTSWm
    [  FAILED  ] ModuleTest.FTST
    [  FAILED  ] ModuleTest.FUCOM
    [  FAILED  ] ModuleTest.FUCOMIP_STFr
    [  FAILED  ] ModuleTest.FUCOMI_STFr
    [  FAILED  ] ModuleTest.FUCOMP
    [  FAILED  ] ModuleTest.FUCOMPP
    [  FAILED  ] ModuleTest.FUCOMP_STFr
    [  FAILED  ] ModuleTest.FUCOM_STFr
    [  FAILED  ] ModuleTest.FXAM
    [  FAILED  ] ModuleTest.FXCH
    [  FAILED  ] ModuleTest.FXCH_STFr
    [  FAILED  ] ModuleTest.FXRSTOR
    [  FAILED  ] ModuleTest.FXSAVE
    [  FAILED  ] ModuleTest.FXTRACT
    [  FAILED  ] ModuleTest.FYL2X
    [  FAILED  ] ModuleTest.FYL2XP1
    [  FAILED  ] ModuleTest.LEAVE
    
    85 FAILED TESTS

