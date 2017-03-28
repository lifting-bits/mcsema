#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

short foo(int a)
{
    int r;
    
    srand(time(NULL));
    r = rand(); 
    return (short)(r + a);
}

int main(int argc, char **argv)
{
    int a;
    unsigned long b;
    short c;
    a = argc;
    b = strlen(argv[0]);
    printf("a = %d (%lu bytes)\n", a, sizeof(a));
    printf("b = %lu (%lu bytes)\n", b, sizeof(b));
    c = foo(a);
    printf("c = %d (%lu bytes)\n", c, sizeof(c)); 
    return 0;
}
