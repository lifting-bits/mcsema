#ifndef COMMON_DEFAULTS_H
#define COMMON_DEFAULTS_H

    #define LINUX_TRIPLE        "i686-pc-linux-gnu"
    #define WINDOWS_TRIPLE      "i686-pc-win32"

    #ifdef __linux__
        #define DEFAULT_TRIPLE LINUX_TRIPLE
    #elif defined(_WIN32)
        #define DEFAULT_TRIPLE WINDOWS_TRIPLE
    #else
        // keep at win32 for now
        #define DEFAULT_TRIPLE WINDOWS_TRIPLE
    #endif

#endif //COMMON_DEFAULTS_H
