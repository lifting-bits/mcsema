#include <stdio.h>

extern int switches(int);

int main(int argc, char *argv[]) {
    int i = 0;

    for(i = 0; i <= 255; i++) {
        switches(i);
    }
    return 0;
}
