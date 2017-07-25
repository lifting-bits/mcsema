# script for mc-sema for mips demo

mipsel-linux-gnu-gcc -fno-stack-protector -o world world.c

./mcsema-disass --disassembler /home/embd-sec/ida-6.95/idal --arch mipsl --os linux --output world.cfg --binary /home/embd-sec/stranger/mcsema/bin/world --entrypoint main

./mcsema-lift -arch mipsl --os linux --cfg world.cfg --entrypoint main --output world.bc

opt-3.8 -O3 -o world_opt.bc world.bc

llvm-dis-3.8 world_opt.bc

