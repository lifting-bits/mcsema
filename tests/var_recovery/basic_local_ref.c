int foo(int bar)
{
	int baz;
	int *bif;
	baz = 17;
	bif = &baz;
	*bif += bar;
	return baz + *bif + bar;
}

int main(int argc, char **argv)
{
	int m;
	m = 3;
	return foo(m);
}
