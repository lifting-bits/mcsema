/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
#include <stdio.h>

static const int A [] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
static const int b [] = { 4, 7, 11 };
static int c [3] = { 0 };

int main (int argc, char **argv)
{
    for (int i = 0; i < 3; ++i)
    {
        for (int j = 0; j < 3; ++j)
        {
            c [i] += A [3 * i + j] * b [j];
        }
    }

    printf ("c = ( %d, %d, %d )^T\n", c [0], c [1], c [2]);

    return 0;
}
