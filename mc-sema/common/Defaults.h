#ifndef COMMON_DEFAULTS_H
#define COMMON_DEFAULTS_H

#define LINUX_TRIPLE        "i686-pc-linux-gnu"
#define LINUX_TRIPLE_X64	"x86_64-unknown-unknown"
#define WINDOWS_TRIPLE      "i686-pc-win32"
#define WINDOWS_TRIPLE_X64  "x86_64-pc-win32"

#ifdef __linux__
# define DEFAULT_TRIPLE LINUX_TRIPLE
# define DEFAULT_TRIPLE_X64  LINUX_TRIPLE_X64
#elif defined(_WIN32)
# define DEFAULT_TRIPLE WINDOWS_TRIPLE
# define DEFAULT_TRIPLE_X64 WINDOWS_TRIPLE_X64
#else
// keep at win32 for now
# define DEFAULT_TRIPLE WINDOWS_TRIPLE
# define DEFAULT_TRIPLE_X64 WINDOWS_TRIPLE_X64
#endif

#endif //COMMON_DEFAULTS_H
