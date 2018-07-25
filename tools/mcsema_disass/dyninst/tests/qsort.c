#include <stdio.h>
#include <stdlib.h>

void fill() {
    printf(" F ");
}

int compare( const void* a, const void* b ) {
    int arg1 = *( const int* ) a;
    int arg2 = *( const int* ) b;
    if ( arg1 < arg2 ) return -1;
    if ( arg1 > arg2 ) return 1;
    return 0;
}

int main() {
    int arr[] = { - 2, 5, 6, 8, 10, 12 };
    int size = sizeof arr / sizeof *arr;

    qsort( arr, size, sizeof( int ), compare );
    int prev = -42;
    printf( "Sorted: " );
    for ( int i = 0; i < size; ++i ) {
        printf("%i ", arr[i] );
        fill();
    }
    printf("\n");
}
