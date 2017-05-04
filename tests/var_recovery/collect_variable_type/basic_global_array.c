#include <stdio.h>
int global_var[16];

int foo()
{
	global_var[0] = 0x41414141;
	global_var[7] = 0x42424242;
	return 0;
}

int bar()
{
	int *ptr = global_var;
	ptr[3] = 0x61616161;
	return 0;
}

void print_global()
{
	int i;
	printf("global_var = [");
	printf("%x", global_var[0]);
	for (i = 1; i < 16; ++i)
	{
		printf(", %x", global_var[i]);
	}
	printf("]\n");
}
int main(int argc, char **argv)
{
	int m;
	print_global();
	m = 0;
	foo();
	bar();
	print_global();
	return m;
}
