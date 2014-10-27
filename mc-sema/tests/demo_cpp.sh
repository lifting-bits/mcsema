#!/bin/bash

echo "Re-linking C++ applications is not yet supported due to unsupported relocation types and possibly other issues"
echo "Uncomment these lines to see what works so far"
exit 0

source env.sh

rm -f demo_cpp.bc demo_cpp.cfg

${CXX} -ggdb -m32 -o demo_cpp demo_cpp.cpp

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -ignore-native-entry-points -d -func-map=linux_map.txt -i=demo_cpp -entry-symbol=main
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -ignore-native-entry-points -d -func-map=linux_map.txt -i=demo_cpp -entry-symbol=main
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_cpp.cfg -driver=mcsema_main,main,2,return,C -o demo_cpp.bc

${LLVM_PATH}/opt -O3 -o demo_cpp_opt.bc demo_cpp.bc 
${LLVM_PATH}/llc -filetype=obj -o demo_cpp.o demo_cpp_opt.bc

${CXX} -m32 -ggdb -o demo_cpp.exe driver_cpp.cpp demo_cpp.o 
./demo_cpp.exe
