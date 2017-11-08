#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LEN 16

int main(int argc, char **argv)
{
    int a;
    unsigned long b;
    char c;
    char d[LEN] = {0};
    int i = 0;

    a = argc;
    b = strlen(argv[0]);
    if(a < b)
    {
        c = argv[0][a];
    }
    else
    {
        c = argv[0][0];
    }
    for(; i < LEN && i < b; i++)
    {
        d[i] = argv[0][i] ^ (char)a;
    }

    printf("a = %d (%lu bytes)\n", a, sizeof(a));
    printf("b = %lu (%lu bytes)\n", b, sizeof(b));
    printf("c = 0x%02x (%lu bytes)\n", c, sizeof(c));
    printf("d = [...] (%lu bytes)\n", sizeof(d));

    return 0;
}
