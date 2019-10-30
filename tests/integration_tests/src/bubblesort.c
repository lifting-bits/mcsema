/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: 12 */
/* TEST: 14 */
/* TEST: 0 */
/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
