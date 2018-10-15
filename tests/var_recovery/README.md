# Test Instructions

Build debug and nondebug binaries for testing:

```sh
mkdir build
cd build
cmake ..
cmake --build .
make install
```

## Recover & Compare Globals

Be sure to set the proper paths in `recover_and_test.sh`. It should (hopefully) warn you if something is missing.

```sh
./recover_and_test.sh
```

## Look at the results

```sh
cat bin/amd64/linux/*_compare.log
```

On my current system, the output is:

```
Comparing NODEBUG [bin/amd64/linux/array_global_amd64_nd_vars.protobuf] vs. DWARF [bin/amd64/linux/array_global_amd64_debug_vars.protobuf]
Globals in NODEBUG but *not* in DWARF: 2
        600e20 601060
Globals in DWARF but *not* NODEBUG: 0
Common globals: 1
        Variables at 601080 disagree on size. 8 [NODEBUG] vs. 200 [DWARF]
Total size disagreements: 1
Comparing NODEBUG [bin/amd64/linux/array_struct_global_amd64_nd_vars.protobuf] vs. DWARF [bin/amd64/linux/array_struct_global_amd64_debug_vars.protobuf]
Globals in NODEBUG but *not* in DWARF: 2
        600e20 601060
Globals in DWARF but *not* NODEBUG: 0
Common globals: 1
        Variables at 601080 disagree on size. 8 [NODEBUG] vs. 400 [DWARF]
Total size disagreements: 1
Comparing NODEBUG [bin/amd64/linux/multi_global_amd64_nd_vars.protobuf] vs. DWARF [bin/amd64/linux/multi_global_amd64_debug_vars.protobuf]
Globals in NODEBUG but *not* in DWARF: 2
        600e20 60104f
Globals in DWARF but *not* NODEBUG: 0
Common globals: 4
Total size disagreements: 0
Comparing NODEBUG [bin/amd64/linux/single_global_amd64_nd_vars.protobuf] vs. DWARF [bin/amd64/linux/single_global_amd64_debug_vars.protobuf]
Globals in NODEBUG but *not* in DWARF: 2
        600e20 601048
Globals in DWARF but *not* NODEBUG: 0
Common globals: 1
Total size disagreements: 0
Comparing NODEBUG [bin/amd64/linux/struct_global_amd64_nd_vars.protobuf] vs. DWARF [bin/amd64/linux/struct_global_amd64_debug_vars.protobuf]
Globals in NODEBUG but *not* in DWARF: 5
        600e20 601068 60106c 601050 60106e
Globals in DWARF but *not* NODEBUG: 0
Common globals: 1
        Variables at 601060 disagree on size. 8 [NODEBUG] vs. 10 [DWARF]
Total size disagreements: 1
Comparing NODEBUG [bin/amd64/linux/union_global_amd64_nd_vars.protobuf] vs. DWARF [bin/amd64/linux/union_global_amd64_debug_vars.protobuf]
Globals in NODEBUG but *not* in DWARF: 2
        600e20 601050
Globals in DWARF but *not* NODEBUG: 0
Common globals: 1
Total size disagreements: 0
```
 

