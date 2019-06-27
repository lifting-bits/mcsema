New attempt to create a better test suite. In development process, use at your own peril.

Directory structure:

get_cfg.py # script to create new cfg files
run_tests.py # runs the selected batch
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
 |- binary_name
 |  |- input1.txt
 |  |- program1
 |- ...
