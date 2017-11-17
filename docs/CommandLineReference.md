# McSema Command Line Reference

## mcsema-disass

Usage: mcsema-disass --disassembler _path-to-IDA_ --os _operating-system_ --arch _architecture_ --output _cfg-path_ --binary _input-binary_ --entrypoint _function_ [--log_file _log-path_]

Where:

* `path-to-IDA` = the path to your IDA Pro disassembler executable, e.g., `~/ida-6.9/idal64`
* `operating-system` = the OS _of the binary being disassembled_: `linux`, or `windows`
* `architecture` = the instruction set architecture _of the binary being disassembled_: `amd64`, `amd64_avx`, `x86`, `x86_avx`, or `aarch64` (64-bit ARMv8)
* `cfg-path` = the path a .cfg file where you want the recovered control flow graph to be saved
* `input-binary` = the path to a binary executable to be disassembled
* `function` = the entry point function where the disassembler should start recovering control flow, e.g., `main`
* `log-path` = (optional) the path to a log file to save the logging output of McSema

## mcsema-lift

Usage: mcsema-lift --arch _architecture_ --os _platform_ --cfg _cfg-path_ [--output _output-path_]

Where:

* `architecture` = architecture to use for the instruction semantics during lifting: `amd64`, `amd64_avx`, `x86`, `x86_avx`, or `aarch64` (64-bit ARMv8)
* `platform` = the operating system _of the binary that was disassembled_ to generate this CFG. Currently the valid options are `linux` or `windows`. This option is required for certain aspects of translation, like ABI compatibility for external functions, etc.
* `cfg-path` = path to the control flow graph file emitted by `mcsema-disass` that you want to convert into bitcode
* `output-path` = path to a .bc file where you want the lifted code to be saved. If the `--output` option is not specified, the bitcode will be written to stdout