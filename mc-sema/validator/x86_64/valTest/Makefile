all: tests.out

tests.out: test
	pin -t $$PWD/../valTool/obj-intel64/val.so -- ./test

test: test_a.o test.o
	gcc -m64 -o test test.o test_a.o

test_a.o: test_a.asm
	nasm -f elf64 -o test_a.o test_a.asm

test.o: test.c
	gcc -m64 -c -o test.o test.c

clean:
	rm -f *.o tests.out
