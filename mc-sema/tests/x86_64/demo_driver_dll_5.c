#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

extern const char* who_is_spartacus(void);
extern const char* who_is_spartacus2(void);
extern const char* get_response(void);

int main(int argc, char *argv[]) {
    DWORD dwRet;

    printf("Who is Spartacus?\n");
    who_is_spartacus();
    printf("Answer: %s\n", get_response());
    printf("... wait ...\n");
    who_is_spartacus2();
    printf("Another Answer: %s\n", get_response());

    return 0;
}
