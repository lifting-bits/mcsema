#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern const char* d_who_spartacus(void);
extern const char* d_who_spartacus_2(void);
extern const char* d_get_response(void);

int main(int argc, char *argv[]) {
    DWORD dwRet;

    printf("Who is Spartacus?\n");
    d_who_spartacus();
    printf("Answer: %s\n", d_get_response());
    printf("... wait ...\n");
    d_who_spartacus2();
    printf("Another Answer: %s\n", d_get_response());

    return 0;
}
