#include <stdio.h>

int main (int argc, char **argv)
{
    int x = 93;
    int *y = &x;
    int **z = &y;

    printf ("  x: %d\n",   x);
    printf (" *y: %d\n",  *y);
    printf ("**z: %d\n", **z);

    return 0;
}
