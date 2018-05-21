# Building Integration Tests
The `test_suite` directory is automatically generated!

All modifications should happen to `test_suite_generator`

## Building `test_suite_generator`:

Install ADA Langauge Support for CMake:

```sh
git clone git@github.com:offa/cmake-ada.git
cd cmake-ada
sudo cmake -P install.cmake
```

Build the tests:

```sh
cd test_suite_generator
mkdir build
cd build
export TRAILOFBITS_LIBRARIES=<path to remill libraries>
export IDAL64_PATH=<path to idal64>
export CMAKE_PROGRAM_PATH=$(dirname ${IDAL64_PATH})
cmake ..
make
make install #install to ../test_suite

#example: 
#export TRAILOFBITS_LIBRARIES=/store/artem/git/remill/remill-build/libraries/
#export IDAL64_PATH=/home/artem/ida-6.9/idal64
#export CMAKE_PROGRAM_PATH=$(dirname ${IDAL64_PATH})
#cmake ..
```
