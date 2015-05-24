#ifdef _WIN32
#include <windows.h>
#else
#include <string.h>
#endif

void foo(void) {
    return;
}

int checkFn(char *f) {
    char *foostr = "foo";
    return strcmp(f, foostr);
}

