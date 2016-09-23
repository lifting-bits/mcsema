#include <stdlib.h>

extern int mcsema_main(int argc, const char *argv[]);

int main(int argc, const char *argv[]) {
    int rv =  mcsema_main(argc, argv);
    return rv;
}
