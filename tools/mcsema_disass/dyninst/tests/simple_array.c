#include <stdio.h>

static const int array [10] = { 4, 7, 9, 13, 1, 7, 1, 0, 4, 5 };

int main (void)
{
    int result = 0;

    for (int i = 0; i < 10; ++i)
        result += array [i];

    printf ("Result: %d\n", result);

    return 0;
}
