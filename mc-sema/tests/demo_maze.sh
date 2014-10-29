#!/bin/bash

source env.sh

rm -f demo_maze demo_maze.bc demo_maze.cfg demo_maze_opt.bc demo_maze_out.exe

${CC} -ggdb -m32 -o demo_maze demo_maze.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -func-map=maze_map.txt -i=demo_maze -entry-symbol=main
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -func-map=maze_map.txt -i=demo_maze -entry-symbol=main
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_maze.cfg -driver=mcsema_main,main,raw,return,C -o demo_maze.bc
${LLVM_PATH}/opt -O3 -o demo_maze_opt.bc demo_maze.bc
${LLVM_PATH}/llc -filetype=obj -o demo_maze.o demo_maze_opt.bc

${CC} -m32 -ggdb -o demo_maze_out.exe driver_maze.c demo_maze.o

echo "ssssddddwwaawwddddssssddwwww" | ./demo_maze_out.exe
