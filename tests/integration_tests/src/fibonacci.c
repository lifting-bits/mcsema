/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: 12 */
/* TEST: 26 */
/* TEST: 2 */
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
