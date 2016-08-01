
struct biff
{
	int a;
	int b;
	char *c;
	short d;
	char e[4];
} ;

int foo(int first, struct biff *baz)
{
	int bar;
	bar = first * 2;
	bar += baz->b;
	baz->a = bar - baz->d;
	return bar;
}

int main(int argc, char **argv)
{
	int m;
	struct biff baz;
	baz.a = 4;
	baz.b = -4;
	baz.d = 15;
	baz.e[0] = 'a';
	baz.e[1] = 'b';
	baz.e[2] = 'c';
	baz.e[3] = '\0';

	m = foo(11, &baz);

	return 0;
}
