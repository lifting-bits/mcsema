#include <stdlib.h>
#include <stdio.h>

extern int HelloWorld(void);

int main(int argc, char *argv[]) {
    printf("About to do msgbox...\n");
    HelloWorld();
    return 0;
}
