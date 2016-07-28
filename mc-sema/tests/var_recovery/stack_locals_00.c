#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    int a;
    unsigned long b;
    a = argc;
    b = strlen(argv[0]);
    printf("a = %d (%lu bytes)\n", a, sizeof(a));
    printf("b = %lu (%lu bytes)\n", b, sizeof(b));
    return 0;
}
