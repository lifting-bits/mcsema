#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define _CRT_SECURE_NO_WARNINGS

extern void demo3(const char *, const char*);

int main(int argc, char *argv[]) {
    size_t  len = sizeof("/first/test/path");
    char    *a = malloc(len);
    char    *b = malloc(len);

    memset(b, 0, len);
    strcpy(a, "/first/test/path");

    demo3(a, b);

    printf("%s -> %s\n", a, b);

    free(a);
    free(b);

    return 0;
}
