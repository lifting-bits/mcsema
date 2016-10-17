#ifdef WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//extern void STDCALL sub_b(RegState *);
extern char* doTrans(char *);

int main(int argc, char *argv[]) {
    size_t  len = sizeof("/first/test/path");
    char    *a = malloc(len);
    char    *b;

    strcpy(a, "/first/test/path");

    b = doTrans(a);

    printf("%s -> %s\n", a, b);

    free(a);
#ifdef WIN32
    HeapFree(GetProcessHeap(), 0, b);
#else
    free(b);
#endif

    return 0;
}
