#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define HANDLE int
#define INVALID_HANDLE_VALUE (-1)
#define CloseHandle(x) close(x)
#endif

void bar(void) {
    return;
}

int foo(char *p) {
    HANDLE  h;
#ifdef WIN32
    h = CreateFileA(p,
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
#else
    h = open(p, O_RDONLY);
#endif

    if( h != INVALID_HANDLE_VALUE ) {
        CloseHandle(h);
        return 0;
    } else {
        return -1;
    }
}
