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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

static char someglobal = 1;
static int gInt[2] = {42, 43};

int writeit()
{
    write(2,&someglobal,1);
    someglobal++;
    write(2,&someglobal,1);
    return 0;
}

int main(void)
{
    someglobal = 0x68;
    writeit();
    gInt[1] = 44;
    printf("\n");
    printf("%i, %i\n", gInt[0], gInt[1]);
    return 0;
}
