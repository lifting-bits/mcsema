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
int main(int argc, char **argv)
{
	int m;
	m = 0;
	foo();
	bar();
	return m;
}
