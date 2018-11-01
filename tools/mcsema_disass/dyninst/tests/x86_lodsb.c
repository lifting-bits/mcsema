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

static inline int mystrcmp(const char *cs,const char *ct)
{
    register int __res;
    __asm__ __volatile__(
            "cld\n"
            "1:\n"
            "lodsb\n"
            "scasb\n"
            "jne 2f\n"
            "testb %%al,%%al\n"
            "jne 1b\n"
            "xorl %%eax,%%eax\n"
            "jmp 3f\n"
            "2:\n"
            "sbbl %%eax,%%eax\n"
            "orb $1,%%al\n"
            "3:\n"
            :"=a" (__res):"S" (cs),"D" (ct):"si","di");
    return __res;
}

static inline char *mystrcpy(char *dest, const char *src)
{
    int d0, d1, d2;
    __asm__ __volatile__(  "1:\n\t"
            "\tlodsb\n\t"
            "stosb\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b"
            : "=&S" (d0), "=&D" (d1), "=&a" (d2)
            : "0" (src),"1" (dest)
            : "memory");
    return dest;
}

int main(void)
{
    int i;
    char buf[] = "i am really cool too\n";
    char str[] = "i am so cool........\n";
    char *ret = mystrcpy(buf, str);
    for (i=0;i<13;i++)
        printf ("%c", buf[i]);
    printf("\n");

    buf[13] = '\0';

    if(mystrcmp("i am so cool.", buf) == 0) {
        printf("The strings match\n");
    } else {
        printf("The strings do not match\n");
    }

    return 0;
}
