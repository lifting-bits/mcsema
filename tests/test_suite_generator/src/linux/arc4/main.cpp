#include "arc4.h"

#include <cstdio>
#include <cstring>

int main() {
  const char password[] = "password";
  const uint8_t data[] = "Hello, world!";

  arc4_ctx_t ctx;
  uint8_t buffer1[sizeof(data)] = {};
  arc4_setkey(&ctx, reinterpret_cast<const uint8_t *>(password),
              sizeof(password) - 1);
  arc4_encrypt(&ctx, buffer1, data, sizeof(data));

  uint8_t buffer2[sizeof(data)] = {};
  arc4_setkey(&ctx, reinterpret_cast<const uint8_t *>(password),
              sizeof(password) - 1);
  arc4_decrypt(&ctx, buffer2, buffer1, sizeof(buffer1));

  std::printf("%s\n", buffer2);
  if (std::memcmp(data, buffer2, sizeof(data)) != 0) {
    return 1;
  }

  return 0;
}
