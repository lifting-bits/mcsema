#include "stddef.h"
void klee_make_symbolic(void *addr, size_t nbytes, const char *name);
void klee_assume(uintptr_t condition);
void klee_alloc(unsigned int size);
void klee_dealloc(void *ptr);
