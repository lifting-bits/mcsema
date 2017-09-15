#include <stdio.h>
#include <stdlib.h>

void bubbleSort (int a [], int array_size)
{
    int i, j, temp;

    for (i = 0; i < array_size - 1; ++i)
    {
        for (j = 0; j < array_size - 1 - i; ++j)
        {
            if (a [j] > a [j+1])
            {
                temp = a [j+1];
                a [j+1] = a [j];
                a [j] = temp;
            }
        }
    }
}

int main (int argc, char **argv)
{
    if (argc < 2)
        return 1;

    int size = atoi (argv [1]);
    int i = 0;
    int array [size];

    for (int i = 0; i < size; ++i)
        array [i] = size - i;

    printf ("Before sorting the list is: \n");

    for(i = 0; i < size; ++i)
    {
        printf ("%d ", array [i]);
    }

    bubbleSort (array, size);

    printf ("\nAfter sorting the list is: \n");

    for(i = 0; i < size; ++i)
    {
        printf ("%d ", array [i]);
    }

    printf("\n");

    return 0;
}
