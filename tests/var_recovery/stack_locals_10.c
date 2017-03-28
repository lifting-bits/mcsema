#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    int a;
    unsigned long b;
    char c;
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
    printf("a = %d (%lu bytes)\n", a, sizeof(a));
    printf("b = %lu (%lu bytes)\n", b, sizeof(b));
    printf("c = 0x%02x (%lu bytes)\n", c, sizeof(c));
    return 0;
}
