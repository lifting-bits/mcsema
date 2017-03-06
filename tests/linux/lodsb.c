#include <stdio.h>

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

}
