#include <stdint.h>
#include <stdlib.h>

extern int vulnerable(const char *input);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    vulnerable((const char *)(data));
    return 0;
}
