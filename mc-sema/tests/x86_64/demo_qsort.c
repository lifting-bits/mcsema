#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

//void qsort_r(void *base, size_t nmemb, size_t size,
//        int (*compar)(const void *, const void *, void *),
//        void *arg);
//
//

static int compar(const void *p, const void *q, void *z) {
    int p_i = *((int*)p);
    int q_i = *((int*)q);
    return p_i - q_i;
}

int print_it(const char *msg) {
    int arr[] = {1,2,3,31337,9,8,7,6};
    int i = 0;

    fprintf(stderr, "%s\n", msg);
    for(i = 0; i < sizeof(arr)/sizeof(arr[0]); i++) {
        fprintf(stderr, "%d ", arr[i]);
    }

    qsort_r(arr, sizeof(arr)/sizeof(arr[0]), sizeof(arr[0]), compar, NULL);
    fprintf(stderr, "\n");

    for(i = 0; i < sizeof(arr)/sizeof(arr[0]); i++) {
        fprintf(stderr, "%d ", arr[i]);
    }
    fprintf(stderr, "\n");
    return 0;
}

#if 0
int main(int arg, const char *argv[]) {
    print_it("Sorting numbers:");
    return 0;
}
#endif
