#include <stdio.h>
#include <stdint.h>

int vulnerable(const char *arg) {
    if(arg[0] == 'f') {
        if(arg[1] == 'u') {
            if(arg[2] == 'z') {
                if(arg[3] == 'z') {
                    if(arg[4] == '\0') {
                        return 0;
                    } else {
                        // lets deref some user specified memory
                        int** z = (int**)((void*)(arg+4));
                        return **z;
                    }
                }
            }
        }
    }
    return -1;
}

#ifdef SOURCE_FUZZ
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    vulnerable((const char *)Data);
    return 0;  // Non-zero return values are reserved for future use.
}
#else
int main(int argc, const char *argv[]) {

    if(argc != 2) {
        printf("Usage:\n");
        printf("%s: <text>\n", argv[0]);
        return 1;
    }

    if(0 == vulnerable(argv[1])) {
        printf("Processed correctly\n");
    } else {
        printf("Bad input\n");
    }

    return 0;
}
#endif
