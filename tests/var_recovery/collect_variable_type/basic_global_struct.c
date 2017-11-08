#include <stdio.h>

int global_var;
struct global_struct_t {
	char title[50];
	char author[50];
	int year;
} global_struct;

int foo(int fooVar)
{
	int m;
	struct global_struct_t *gs;
	global_var = 4;
	gs = &global_struct;
	char *title = gs->title;
	title[5] = 'c';
	m = fooVar + gs->year;
	gs->year = 5;
	return m;
}

int ref(struct global_struct_t *gs)
{
	if (gs == 0) return 0;
	gs->year = 10;
	gs->author[4] = 'm';
	return (int) gs->title[1];
}

void print_50_chars(char* str)
{
	int i;
	for (i = 0; i < 50; ++i)
	{
		printf("%x ", (unsigned char)str[i]);
	}
}

void print_global_struct()
{
	printf("global_struct.year = %d\n", global_struct.year);
	printf("global_struct.title = ");
	print_50_chars(global_struct.title);
	printf("\nglobal_struct.author = ");
	print_50_chars(global_struct.author);
	printf("\n");
}

int main(int argc, char **argv)
{
	int m;
	print_global_struct();
	global_struct.year = 14;
	global_struct.title[0] = 'a';
	global_struct.author[0] = 'b';
	ref(&global_struct);
	m = foo(4);
	print_global_struct();
	return m;
}
