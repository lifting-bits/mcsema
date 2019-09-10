New attempt to create a better test suite. In development process, use at your own peril.

Use:

1) You can use `populate.py` to copy binaries to be tested from `/bin` or `/usr/bin`.
Directory that contains tags is iterated and each binary that has present tag file is searched for.
In case it is not found error is written on standard output, but the script continues with the rest.

Example:

```
./populate.py
 > not_exists not found anywhere
 > Found /bin/echo
 > Found /bin/gre
```

2) In case you want to try your own sources you can use `compile.py` which compiles all sources from `src` directory. If option `--stub_tags` is used, the corresponding tag files are created.

3) First create a batch of cfg file using `get_cfg.py` -- you can select flavors to run only subset of all tests (they are specified in `tags` directory).
  + tag all will get cfg for every file in `bin`
  + there are several policies that allows modification of already existing batches

Example:
```
# Every file present in the `bin` directory will be lifted into cfg file.
# If a batch with name first_batch is present it will be deleted.
python get_cfg.py --disass dyninst --flavors all --batch first_batch --batch_policy D

# Lifts all missing files that have flavor C. In case some file has already present cfg,
# it is not replaced
python get_cfg.py --disass dyninst --flavors C --batch first_batch --batch_policy C

# Updates all files with flavor echo, leaves rest of the batch untouched
python get_cfg.py --disass dyninst --flavors echo --batch first_batch --batch_policy U
```

4) Once batch is created `run_tests.py` can be run

Extending test:

To extend tests (for new binary B) several things should be provided:

Do not use "." (dot) in the name of the tested binaries! (Use "_" or something else)
* binary B should be stored in `bin` folder (`compile.py` or `populate.py` can be used)
* appropriate tags should be specified in `tags` folder (`tags/B.tag`)
* in `run_tests.py` special class names `B_suite` (correct naming is important!) should be
  implemented -> the actual tests are specified here

There are two classes new B_suite can inherit from:
* `BaseTest` - provides all the necessary methods to do the actual testing (setup, input setup,
  execution, actual comparison, cleanup) -- it is not necessary the new suite inherits from this
  class but it is recommended
* `BasicTest` - provides tests for `--help` and `--version` invocations, which are typical uses
  of many binaries

Example of the test class hierarchy:

    BaseTest
   _____|_____
   |         |
BasicTest   custom_binary_suite
   |
readelf_suite

For each invocation of the binary separate method in the B_suite should be implemented:
We already have:

```
class B_suite(BaseTest):
  pass
```

Let's say we want to test invocation with `--help` as command line argument, therefore we need to
add a method to `B_suite`. It is important the name of the method starts with `test_` since
`unittest` is used.

```
class B_suite(BaseTest):
  def test_help(self):
    self.wrapper(["--help"], [])

```

`BaseTest::wrapper` is used since it does some statistics over the suite.
First argument are the command line arguments,
second are the files that may be used by the program (the file must reside in `inputs`).

In the case the invocation creates file as byproduct, the method needs to be slightly modified:

```
def test_output(self):
  self.wrapper(["--input data.txt", "--outout data.compressed"], ["data.txt"])
  self.check_files("data.compressed")
```
Both original and recompiled binary create their own version of `data.compressed` and these files
are compared. In case they are different the test is a failure.

Please note that `data.txt` must be inside `inputs` folder, i.e.`inputs/data.txt` must exist.


Directory structure:

get_cfg.py # script to create new cfg files
run_tests.py # runs the selected batches
populate.py # tries to copy binaries from `/bin` or `/usr/bin` based on tags files
bin
  |- base_test
  |- ... rest of tested binaries

tags
  |- base_test.flag
  |- ... for each binary a list of its tags (flavors)

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
