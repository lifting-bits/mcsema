#include <stdio.h>

int main (void)
{
    int array [10];
    int sum = 0;

    for (int i = 0; i < 10; ++i)
        array [i] = 2 * i;

    for (int i = 0; i < 10; ++i)
        sum += array [i];

    printf ("Result: %d\n", sum);

    return 0;
}
