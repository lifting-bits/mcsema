#include <stdio.h>
#include <stdlib.h>

unsigned int fib (unsigned int i)
{
    if (i == 0)
        return 0;
    else if ((i == 1) || (i == 2))
        return 1;
    else
        return fib (i - 1) + fib (i - 2);
}

int main (int argc, char **argv)
{
    if (argc < 2)
        return 1;

    int n = atoi (argv [1]);
    printf ("%u\n", fib (n));

    return 0;
}
