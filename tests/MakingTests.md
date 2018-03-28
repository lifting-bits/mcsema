# Building Integration Tests
The `test_suite` directory is automatically generated!

All modifications should happen to `test_suite_generator`

How to build `test_suite_generator`:

```sh
cd test_suite_generator
mkdir build
cd build
export TRAILOFBITS_LIBRARIES=<path to remill libraries>
export IDAL64_PATH=<path to idal64>

cmake ..

#example: 
#export TRAILOFBITS_LIBRARIES=/store/artem/git/remill/remill-build/libraries/
#export IDAL64_PATH=/home/artem/ida-6.9/idal64
#export CMAKE_PROGRAM_PATH=$(dirname ${IDAL64_PATH})
#cmake ..


```
