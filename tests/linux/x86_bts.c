#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

int main(void)
{
    unsigned int x = 0xdeadbee0;
    unsigned int n = 3;
    __asm__ __volatile__ ( "bts %1,%0": "+rm"(x) : "r"(n));
    printf("x is: %08x\n", x);
    return 0;
}
