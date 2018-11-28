# Building Integration Tests
The `test_suite` directory is automatically generated!

All modifications should happen to `test_suite_generator`

## Building `test_suite_generator`:

Build the tests:

```sh
cd test_suite_generator
mkdir build
cd build
export TRAILOFBITS_LIBRARIES=<path to remill libraries>
export IDAT64_PATH=<path to idat64>
export CMAKE_PROGRAM_PATH=$(dirname ${IDAT64_PATH})
cmake ..
make
make install #install to ../test_suite

#example: 
#export TRAILOFBITS_LIBRARIES=/store/artem/git/remill/remill-build/libraries/
#export IDAT64_PATH=/home/artem/ida-7.1/idat64
#export CMAKE_PROGRAM_PATH=$(dirname ${IDAT64_PATH})
#cmake ..
```

# Running the tests

After building and installing, you can do:

```sh
cd test_suite_generator/test_suite
python2 start.py
```
