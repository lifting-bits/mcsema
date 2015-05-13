#include <stdio.h>

extern int demo8_entry(int);

int main(int argc, char *argv[]) {

    int i = demo8_entry(2);
    int k = demo8_entry(4);
    int j = demo8_entry(0);

    printf("i == %d\nk == %d\nj == %d\n", i, k, j);

    return 0;
}
