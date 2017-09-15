#include <stdio.h>

int main (int argc, char **argv)
{
    int array [] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    int result = 0;

    for (int i = 0; i < 10; ++i)
    {
        result += array [i];
        printf ("result now: %d\n", result);
    }

    printf ("final result: %d\n", result);

    return 0;
}
