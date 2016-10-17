#!/bin/bash

source env.sh

rm -f demo_maze demo_maze.bc demo_maze.cfg demo_maze_opt.bc demo_maze_out.exe

${CC} -ggdb -m64 -o demo_maze demo_maze.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -func-map=maze_map.txt -i=demo_maze -entry-symbol=main>> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_maze.cfg -entrypoint=main -o demo_maze.bc
clang-3.5 -O3 -m64 -o demo_maze_out.exe ../../../drivers/ELF_64_linux.S demo_maze.bc

echo "ssssddddwwaawwddddssssddwwww" | ./demo_maze_out.exe
