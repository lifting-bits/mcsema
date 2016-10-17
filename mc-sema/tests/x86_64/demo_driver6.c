#ifdef WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern void doWork(char**, int);

int main(int argc, char *argv[]) {
    char    *foo[3];
    char    *a = malloc(sizeof("foo"));
    char    *b = malloc(sizeof("/stuff/"));
    char    *c = malloc(sizeof("bar"));

    memset(a, 0, sizeof("foo"));
    memset(b, 0, sizeof("/stuff/"));
    memset(c, 0, sizeof("bar"));
    strcpy(a, "foo");
    strcpy(b, "/stuff/");
    strcpy(c, "bar");
   
    foo[0] = a;
    foo[1] = b;
    foo[2] = c;

    printf("a == %s\n", a);
    printf("b == %s\n", b);
    printf("c == %s\n", c);

    doWork(foo, 3);

    printf("a == %s\n", a);
    printf("b == %s\n", b);
    printf("c == %s\n", c);

    return 0;
}
