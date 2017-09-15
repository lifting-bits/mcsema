#include <stdio.h>

static const int g = 8;

int foo (void)
{
    const int *p = &g;

    if ((*p) > 12)
        return 17;

    char str [] = "Hello, world!\n";

    for (int i = 0; i < 14; ++i)
        putchar (str [i]);

    putchar('H');
    putchar('e');
    putchar('l');
    putchar('l');
    putchar('o');
    putchar(',');
    putchar(' ');
    putchar('w');
    putchar('o');
    putchar('r');
    putchar('l');
    putchar('d');
    putchar('!');
    putchar('\n');

    printf ("And now from printf()!\n");

    int i;
    i = 4 + (*p);
    printf ("Calculated %d\n", i + 42);

    return 0;
}

int main (int argc, char **argv)
{
    return foo ();
}
