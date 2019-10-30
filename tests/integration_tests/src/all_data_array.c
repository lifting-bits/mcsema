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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>

int main(int argc, char **args)
{
    uint8_t fold = 0xAF;
    void (*obf_funcs[]) (void) = {
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
        (void (*) (void))main,
    };

    printf("hrm: %zu\n", sizeof (obf_funcs));
    printf("hrm: %zu\n", sizeof (void *));
    printf("div: %zu\n", (sizeof (obf_funcs) / sizeof (void *)));
    fold %= (sizeof (obf_funcs) / sizeof (void *));
    printf("so answer: %d\n", fold);
    return 0;
}
