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

#include <stdio.h>

static int gArr[10] = {1, 2, 3, 3, 2, 1, 1, 2, 3, 42};

int main() {
    printf("%i\n", gArr[0]);
    printf("%i\n", gArr[1]);
    printf("%i\n", gArr[2]);
    printf("%i\n", gArr[3]);
    printf("%i\n", gArr[4]);
    printf("%i\n", gArr[5]);
    printf("%i\n", gArr[6]);
    printf("%i\n", gArr[7]);
    printf("%i\n", gArr[8]);
    printf("%i\n", gArr[9]);
}
