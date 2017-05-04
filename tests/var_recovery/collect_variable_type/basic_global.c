#include <stdio.h>
int global_var;

int foo(int bar)
{
	int baz;
	baz = bar + global_var;
	global_var = baz - 2;
	return baz;
}

int main(int argc, char **argv)
{
	int m;
	printf("global_var = %d\n", global_var);
	global_var = argc;
	m = foo(4);
	printf("global_var = %d\n", global_var);
	return m;
}
