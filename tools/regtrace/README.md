# Debugging control flow divergences

Debugging divergences produced by incorrect instruction translations can be challenging. It helps to have a ground truth against which comparisons can be made. There are several ways to obtain a ground truth: other binary translators (PIN, DynamoRIO), debuggers (GDB), and extensive unit tests.

Sometimes getting a ground truth is easier said than done. Finding the point of divergence of control flow can usually be discovered using GDB. However, often the point of divergence is really a symptom of the true divergence. Pinpointing the true point of divergence can be complicated by minor issues like the runtime address of the call stack being slightly different between GDB and the `mcsema-lift` program executions.

This directory provides a PIN tool that makes it easier to diagnose execution divergences.

## The trace PIN tool

A PIN tool is provided in this directory that. This tool will print a register state trace during the program's execution. This printed format matches what is printed when a program is lifted using the `-add-reg-trace` option to `mcsema-lift`.

The PIN tool can be compiled as follows:

```shell
export PIN_ROOT=/opt/pin-3.2-81205-gcc-linux/
./build.sh
```

The following is an example of how to use this tool.

**Note:** The `PIN_ROOT` environment variable must be defined as the directory containing the `pin` executable. 

```shell
${PIN_ROOT}/pin -t obj-intel64/Trace.so -entrypoint 0x402a00 -- /bin/ls
```

This tool uses PIN to instrument the program `/bin/ls`. The tool prints out (to `/dec/stdout`) the values of all registers before every executed instruction. The output of this program follows the same format as that produced when lifting with `-add-reg-tracer`.
