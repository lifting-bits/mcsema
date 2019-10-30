/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: /usr */
/* TEST: /eqeqeqwe */
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

#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>

int main (int argc, char **argv)
{
    if (argc != 2)
    {
        puts ("error: need exactly one argument");
        return 1;
    }

    DIR *dir = opendir (argv [1]);
    if (!dir)
        perror ("opendir");
    else
        closedir (dir);

    printf ("errno: %d\n", errno);

    return 0;
}
