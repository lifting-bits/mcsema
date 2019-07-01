New attempt to create a better test suite. In development process, use at your own peril.

Use:
* First create a batch of cfg file using `get_cfg.py` -- you can select flavors to run only subset of all tests (they are specified in `tags` directory).
* Once batch is created `run_tests.py` can be run

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
