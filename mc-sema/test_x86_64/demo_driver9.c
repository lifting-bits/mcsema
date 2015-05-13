#include <stdio.h>

extern int demo9_entry(char ch[]);

int main(int argc, char *argv[]) {

    char str[] = "abc";

    demo9_entry(str);

    return 0;
}
