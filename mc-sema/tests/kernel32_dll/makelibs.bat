cl /LD api-ms-win-core-synch-l1-1-0.def api-ms-win-core-synch-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-synch-l1-1-0.exp api-ms-win-core-synch-l1-1-0.obj api-ms-win-core-synch-l1-1-0.dll

cl /LD api-ms-win-core-memory-l1-1-0.def api-ms-win-core-memory-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-memory-l1-1-0.exp api-ms-win-core-memory-l1-1-0.obj api-ms-win-core-memory-l1-1-0.dll

cl /LD ntdll.def ntdll.c /link /NODEFAULTLIB /ENTRY:DllMain
del ntdll.exp ntdll.obj ntdll.dll

cl /LD api-ms-win-core-profile-l1-1-0.def api-ms-win-core-profile-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-profile-l1-1-0.exp api-ms-win-core-profile-l1-1-0.obj api-ms-win-core-profile-l1-1-0.dll

cl /LD api-ms-win-core-debug-l1-1-0.def api-ms-win-core-debug-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-debug-l1-1-0.exp api-ms-win-core-debug-l1-1-0.obj api-ms-win-core-debug-l1-1-0.dll

cl /LD api-ms-win-core-io-l1-1-0.def api-ms-win-core-io-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-io-l1-1-0.exp api-ms-win-core-io-l1-1-0.obj api-ms-win-core-io-l1-1-0.dll

cl /LD api-ms-win-core-util-l1-1-0.def api-ms-win-core-util-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-util-l1-1-0.exp api-ms-win-core-util-l1-1-0.obj api-ms-win-core-util-l1-1-0.dll

cl /LD api-ms-win-core-heap-l1-1-0.def api-ms-win-core-heap-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-heap-l1-1-0.exp api-ms-win-core-heap-l1-1-0.obj api-ms-win-core-heap-l1-1-0.dll

cl /LD api-ms-win-core-localization-l1-1-0.def api-ms-win-core-localization-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-localization-l1-1-0.exp api-ms-win-core-localization-l1-1-0.obj api-ms-win-core-localization-l1-1-0.dll

cl /LD api-ms-win-core-processenvironment-l1-1-0.def api-ms-win-core-processenvironment-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-processenvironment-l1-1-0.exp api-ms-win-core-processenvironment-l1-1-0.obj api-ms-win-core-processenvironment-l1-1-0.dll

cl /LD api-ms-win-core-errorhandling-l1-1-0.def api-ms-win-core-errorhandling-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-errorhandling-l1-1-0.exp api-ms-win-core-errorhandling-l1-1-0.obj api-ms-win-core-errorhandling-l1-1-0.dll

cl /LD api-ms-win-core-sysinfo-l1-1-0.def api-ms-win-core-sysinfo-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-sysinfo-l1-1-0.exp api-ms-win-core-sysinfo-l1-1-0.obj api-ms-win-core-sysinfo-l1-1-0.dll

cl /LD api-ms-win-core-misc-l1-1-0.def api-ms-win-core-misc-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-misc-l1-1-0.exp api-ms-win-core-misc-l1-1-0.obj api-ms-win-core-misc-l1-1-0.dll

cl /LD api-ms-win-core-threadpool-l1-1-0.def api-ms-win-core-threadpool-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-threadpool-l1-1-0.exp api-ms-win-core-threadpool-l1-1-0.obj api-ms-win-core-threadpool-l1-1-0.dll

cl /LD api-ms-win-core-rtlsupport-l1-1-0.def api-ms-win-core-rtlsupport-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-rtlsupport-l1-1-0.exp api-ms-win-core-rtlsupport-l1-1-0.obj api-ms-win-core-rtlsupport-l1-1-0.dll

cl /LD api-ms-win-core-file-l1-1-0.def api-ms-win-core-file-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-file-l1-1-0.exp api-ms-win-core-file-l1-1-0.obj api-ms-win-core-file-l1-1-0.dll

cl /LD api-ms-win-core-libraryloader-l1-1-0.def api-ms-win-core-libraryloader-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-libraryloader-l1-1-0.exp api-ms-win-core-libraryloader-l1-1-0.obj api-ms-win-core-libraryloader-l1-1-0.dll

cl /LD api-ms-win-core-handle-l1-1-0.def api-ms-win-core-handle-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-handle-l1-1-0.exp api-ms-win-core-handle-l1-1-0.obj api-ms-win-core-handle-l1-1-0.dll

cl /LD api-ms-win-core-fibers-l1-1-0.def api-ms-win-core-fibers-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-fibers-l1-1-0.exp api-ms-win-core-fibers-l1-1-0.obj api-ms-win-core-fibers-l1-1-0.dll

cl /LD kernelbase.def kernelbase.c /link /NODEFAULTLIB /ENTRY:DllMain
del kernelbase.exp kernelbase.obj kernelbase.dll

cl /LD api-ms-win-core-string-l1-1-0.def api-ms-win-core-string-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-string-l1-1-0.exp api-ms-win-core-string-l1-1-0.obj api-ms-win-core-string-l1-1-0.dll

cl /LD api-ms-win-core-processthreads-l1-1-0.def api-ms-win-core-processthreads-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-processthreads-l1-1-0.exp api-ms-win-core-processthreads-l1-1-0.obj api-ms-win-core-processthreads-l1-1-0.dll

cl /LD api-ms-win-security-base-l1-1-0.def api-ms-win-security-base-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-security-base-l1-1-0.exp api-ms-win-security-base-l1-1-0.obj api-ms-win-security-base-l1-1-0.dll

cl /LD api-ms-win-core-namedpipe-l1-1-0.def api-ms-win-core-namedpipe-l1-1-0.c /link /NODEFAULTLIB /ENTRY:DllMain
del api-ms-win-core-namedpipe-l1-1-0.exp api-ms-win-core-namedpipe-l1-1-0.obj api-ms-win-core-namedpipe-l1-1-0.dll

