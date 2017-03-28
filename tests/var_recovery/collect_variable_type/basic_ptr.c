int foo(int first, int *second, short(*third)(short))
{
	int bar;
	short baz;
	bar = first * 2;
	bar = *second * (bar + 4);
	baz = (short)bar;
	bar += third(baz);
	return bar;
}

short bim(short m)
{
	short rval;
	rval = m ^ 0xCCCC;
	rval += 35;
	return rval;
}

int main(int argc, char **argv)
{
	int m,n ;
	n = 5;
	m = foo(4, &n, &bim);
	return 0;
}
