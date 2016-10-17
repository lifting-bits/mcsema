#include <stdlib.h>

extern int print_it(const char *msg);

int qsort_driver(const char* words)
{
    return print_it(words);
}

int main(int argc, const char *argv[]) {
	return qsort_driver("Sorted numbers:");
}
