int foo(int first, int second)
{
	int bar;
	bar = first * 2;
	bar = second * (bar + 4);
	return bar;
}

int main(int argc, char **argv)
{
	int m;
	m = foo(4, 37);
	return 0;
}
