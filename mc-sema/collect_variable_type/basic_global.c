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
	global_var = argc;
	m = foo(4);
	return m;
}
