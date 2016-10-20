#include <stdio.h>

extern int printit(char ch[]);

int main(int argc, char *argv[]) {

    char str[] = "abc";

    printit(str);

    return 0;
}
