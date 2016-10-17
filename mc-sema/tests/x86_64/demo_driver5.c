#ifdef _WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int foo(char*);


int main(int argc, char *argv[]) {

#ifdef _WIN32
    int k = foo("c:\\windows\\temp\\foo.txt");
#else
    int k = foo("/tmp/demo5_foo.txt");
#endif
    printf("%d\n", k);

    return k;
}
