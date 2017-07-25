
echo "llvm-as-3.8 ..."
llvm-as-3.8 world_opt.ll -o world_mod.bc

#echo "clang-3.8 ..."
#clang-3.8 -v -O0  -g ../mcsema/generated/ELF_64_linux.S driver.c world_mod.bc -o driver
#clang-3.8 -v -O0  -g ../mcsema/generated/ELF_64_linux.S driver.bc world_mod.bc -o driver

#echo "executing driver"
#./driver

echo "clang-3.8 ..."
clang-3.8 -m32 -DDEMO_KLEE -I/home/embd-sec/stranger/klee/include -emit-llvm -c world-drv.c -o world_drv.bc

echo "llvm-link ..."
llvm-link world_drv.bc world_mod.bc -o world_forklee.bc

echo "klee ..."
klee -emit-all-errors -libc=uclibc -posix-runtime world_forklee.bc 

echo "ktest-tool ..."
ktest-tool klee-last/test000001.ktest
