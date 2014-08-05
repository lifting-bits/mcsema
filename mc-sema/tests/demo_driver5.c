#ifdef _WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int demo5_entry(char*);


int main(int argc, char *argv[]) {

#ifdef _WIN32
    int k = demo5_entry("c:\\windows\\temp\\foo.txt");
#else
    int k = demo5_entry("/tmp/foo.txt");
#endif
    printf("%d\n", k);

    return k;
}
