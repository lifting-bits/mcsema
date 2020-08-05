/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: readdir.c */
/* TEST: /tmp */
/* TEST: file-that-does-not-exist */
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

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void lookup (const char *arg)
{
    DIR *dirp;
    struct dirent *dp;

    if ((dirp = opendir (".")) == NULL)
    {
        perror ("couldn't open '.'");
        return;
    }

    do
    {
        errno = 0;
        if ((dp = readdir (dirp)) != NULL)
        {
            if (strcmp (dp->d_name, arg) != 0)
                continue;

            printf ("found %s\n", arg);
            closedir (dirp);
            return;
        }
    } while (dp != NULL);

    if (errno != 0)
        perror ("error reading directory");
    else
        printf ("failed to find %s\n", arg);

    closedir (dirp);
    return;
}

int main (int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
        lookup (argv [i]);

    return 0;
}
