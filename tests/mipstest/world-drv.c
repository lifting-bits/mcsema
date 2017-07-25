
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../mcsema/Arch/Mips/Runtime/State.h"

#ifdef DEMO_KLEE
#include <klee/klee.h>
#endif

unsigned long stack[4096*10];
RegState reg_state;

#define world_main_raw sub_400890

char password[] = "this";

char *_fgets(char *s, int size, FILE *stream)
{
	reg_state.SP += 8;
	printf("Skipping fgets with stub data.\n");
	strcpy(s, password);
	return s;
}

int _atoi(const char *s)
{
	reg_state.SP += 8;
        //printf("Skipping atoi with stub data.\n");
	int n = atoi(s);
#ifdef DEMO_KLEE
	klee_make_symbolic(&n, sizeof(int), "sym");
#endif
	return n;
}

int _puts(const char *s)
{
	reg_state.SP += 8;
	return puts(s);
}

void _free(void *ptr)
{
	reg_state.SP += 8;
	free(ptr);
}

void *_malloc(size_t size)
{
	reg_state.SP += 8;
	return malloc(size);
}

void *_memcpy(void *dest, const void *src, size_t n)
{
	reg_state.SP += 8;
	return memcpy(dest, src, n);
}

void _exit(int status)
{
	reg_state.SP += 8;
	exit(status);
}
/*
extern void try(RegState *reg_state);

void try_fake(RegState *reg_state)
{
	reg_state->SP += 8;
	int var = (int)reg_state->A0;
#ifdef DEMO_KLEE
	klee_make_symbolic(&var, sizeof(var), "sym");
#else
	//memset(buf, 0, 16);
#endif
	//(*out_buf) = buf;

	int ret = 0;
	reg_state->V0 = (unsigned long)ret;
}*/

extern void world_main_raw(RegState *);

int world_main_driver(int argc, char **argv)
{
	memset(&stack, 0, sizeof(stack));
	memset(&reg_state, 0, sizeof(reg_state));

	reg_state.FP = 0;
	reg_state.SP = (unsigned long)&stack[4096*9];

	reg_state.A0 = (unsigned long)argc;
	reg_state.A1 = (unsigned long)argv;

	world_main_raw(&reg_state);

	return (int)reg_state.V0;
}


int main(int argc, char **argv)
{
	return world_main_driver(argc, argv);
}
