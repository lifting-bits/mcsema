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


2) First create a batch of cfg file using `get_cfg.py` -- you can select flavors to run only subset of all tests (they are specified in `tags` directory).
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

3) Once batch is created `run_tests.py` can be run

Extending test:
To extend tests (for new binary B) several things should be provided:
* binary B should be stored in `bin` folder, currently compiling from sources is not supported
* appropriate tags should be specified in `tags` folder (`tags/B.tag`)
* in `run_tests.py` special class names `B_suite` (correct naming is important!) should be
  implemented -> the actual tests are specified here


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
