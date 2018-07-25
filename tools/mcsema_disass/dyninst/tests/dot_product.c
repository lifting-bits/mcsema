#include <stdio.h>

static const int a [] = { 4, 3, 7, 5, 9, -4 };
static const int b [] = { 1, -1, 5, -2, 3, 5 };

int main (void)
{
    int result = 0;

    for (int i = 0; i < 6; ++i)
        result += a[i] * b[i];

    printf ("%d\n", result);
    return 0;
}
