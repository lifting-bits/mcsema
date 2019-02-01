/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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
