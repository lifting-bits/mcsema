#ifdef _WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int foo(char*);


int main(int argc, char *argv[]) {

#ifdef _WIN32
    char tmp[MAX_PATH+7+1] = {0};
    GetTempPath(MAX_PATH, tmp);
    strcat(tmp, "foo.txt");
    int k = foo(tmp);
#else
    int k = foo("/tmp/demo5_foo.txt");
#endif
    printf("%d\n", k);

    return k;
}
