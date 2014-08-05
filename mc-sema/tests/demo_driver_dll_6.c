#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

//extern DWORD get_value();
extern DWORD d_get_value();

int main(int argc, char *argv[]) {

    DWORD value = d_get_value();
    printf("This should print 42: %d [%x]\n", value, value);
    return 0;
}
