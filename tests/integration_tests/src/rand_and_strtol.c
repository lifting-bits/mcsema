/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
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

#include <stdlib.h>
#include <stdio.h>

int main (void)
{
    int x = -11;
    int y = abs (x);

    printf ("11 : %i\n", y);

    srand (13);

    int i = rand ();
    printf ("rand: %i\n", i);

    char str [30] = "2030300 This is a test";
    char *ptr;
    long ret;

    printf ("str: \"%s\"\n", str);
    ret = strtol (str, &ptr, 10);
    printf ("Number: %ld\n", ret);
    printf ("Remainder: \"%s\"\n", ptr);

    return 0;
}
