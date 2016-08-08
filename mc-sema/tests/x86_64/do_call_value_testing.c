#include <stdio.h>
#include <stdlib.h>

void one(int arg);
int two(int arg0, int arg1, int arg2);

typedef void (*funcptr0)(int);
typedef int (*funcptr1)(int, int, int);

funcptr0 ptrs0[] = {NULL, one, NULL};
funcptr1 ptrs1[] = {NULL, NULL, two};

void one(int arg)
{
    int foo = ptrs1[arg+1](arg+1, 1, 2);
    printf("foo is: %d\n", foo);
}

int two(int arg0, int arg1, int arg2)
{
    printf("arg0 is: %d\n", arg0);
    printf("arg1 is: %d\n", arg1);
    printf("arg2 is: %d\n", arg2);

    return arg0+arg1+arg2;
}

int main(int argc, const char* argv[])
{
    if(argc != 2)
    {
        printf("syntax: %s <int argument>\n(Use '1' for int argument)\n", argv[0]);
        return 0;
    }
    int which = atoi(argv[1]); //input(); // use '1' 
    ptrs0[which](which);
    return which;
}
