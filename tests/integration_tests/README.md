New attempt to create a better test suite. In development process, use at your own peril.

# Use:


1) You can use `populate.py` to copy binaries to be tested from `/bin` or `/usr/bin`.
Directory that contains configs is iterated and each binary that has present at least one config file is searched for.
In case it is not found error is written on standard output, but the script continues with the rest.

    Example:

    ```
    ./populate.py
     > not_exists not found anywhere
     > Found /bin/echo
     > Found /bin/grep
    ```

2) In case you want to try your own sources you can use `compile.py` which compiles all sources from `src` directory. If option `--stub_tags` is used, the corresponding tag files are created.

3) First create a batch of cfg file using `get_cfg.py` -- you can select tags to run only subset of all tests (they are specified in `tags` directory).
    + tag all will get cfg for every file with at least one config present
    + there are several policies that allows modification of already existing batches

    Example:

    ```
    # Every file present in the `bin` directory will be lifted
    # into cfg file.
    # If a batch with name first_batch is present it will be deleted.

    python get_cfg.py --disass dyninst --tags all
                      --batch first_batch --batch_policy D

    # Lifts all missing files that have tags C.
    # In case some file has already present cfg,
    # it is not replaced

    python get_cfg.py --disass dyninst --tags C
                      --batch first_batch --batch_policy C

    # Updates all files with tag echo, leaves rest of the batch untouched

    python get_cfg.py --disass dyninst --tags echo
                      --batch first_batch --batch_policy U
    ```

4) Once batch is created `run_tests.py` can be run.

# Config/Test files (tags/):

Directory tags (name to be changed) contains two types of files (beware, whitespaces are used as delimiters, therefore they matter):

1) `binary.kind.config`, which has following internal structure:

    ```
    TAGS: one two ...
    LIFT_OPTS: +one +two 87 !three
    ```

    `TAGS` specify tags of this config, while `LIFT_OPTS` represent specific lift options. Options prefixed by `+` are added and prefix `!` means that the options is not used even though it would normally be by default.
    One binary can have multiple config files.

    At the moment each config should contain exactly one of the following two tags: `c`, `cpp`. They are later used to determine which compiler to use when recompiling.

2) `binary.test`, which has following internal structure:

    ```
    TEST: cmd_option1 ...
    STDIN: -Fpath/to/file/ or string
    FILES: Not implemented yet
    TEST: ...
    ...
    ```

    For simple test cases it is easier to write this kind of test specification than the one used in python sources.

    `STDIN:` after file is optional and so is `FILES:`. If value of `STDIN:` is prefixed by F corresponding file is loaded (it can be relative to the root of test dir) and used as stdin.

# src/

Files presented in `src` are meant to be compiled by `compile.py` and can have special header:
```
/* TAGS: ... */
/* CC_OPTS: ... */
/* LD_OPTS: ... */
/* LIFT_OPTS: kind1 ... */
/* LIFT_OPTS: kind2 ... */
...
/* TEST: */
/* STDIN: */
...
```
Everything except `CC_OPTS:` and `LD_OPTS:` is used to generated appropriate `.config/.test` files. `CC_OPTS:` and `LD_OPTS:` are forwarded to the compiler.

# Complex tests

Not every test can be described by simple "language" of the `.test` files, therefore it is needed to have a way to define those more complex ones.
In `run_tests.py` a global array `g_complex_test` is present, which is used to store more advanced configurations. It has following data type:

```
{ str : [ TestDetails ] }
```
The structure is rather intuitive -- each binary has one entry and can have multiple test cases stored in array of `TestDetails`. `TestDetails` currently have following options:
```
cmd (set in __init___): array of command line arguments
files: files that are used by the program
       -> it is needed to copy them into appropriate location
check: files that are output of the program
       -> it is needed to compare them
```
As usual, files can be specified by relative paths from root directory of tests.



# Directory structure:

```
get_cfg.py # script to create new cfg files
run_tests.py # runs the selected batches
populate.py # tries to copy binaries from `/bin` or `/usr/bin` based on tags files
bin
  |- base_test
  |- ... rest of tested binaries

tags
  |- base_test.default.config
  |- ... for each binary at least one config file
  |- base.test
  |- .. optional test files

# Folders containing cfg files (there may be a reason you want to have several,
# for example compare frontends or have cfgs of some special flavor)
batch1_cfg
  |- base_test.cfg
  |- ...

batch2_cfg
  |- base_test.cfg
  |- ...

# Symlinks to shared libraries used by original binaries
# Links themselves are created by get_cfg.py
shared_libs
 |- libc.so
 |- ...

# Inputs for the run_tests.py
inputs
|- input1.txt
|- program1
|- ...
```
