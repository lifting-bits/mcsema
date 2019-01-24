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

extern int foo (void);
extern int bar (int);
extern int baz (void);
extern int test (int);

int main (int argc, char **argv)
{
    printf ("foo(): %d (should be: 42)\n", foo ());
    printf ("bar(15): %d (should be: 57)\n", bar (15));
    printf ("baz(): %d (should be: 51)\n", baz ());
    printf ("test(6): %d (should be: 21)\n", test(6));

    return 0;
}
