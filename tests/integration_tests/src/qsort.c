/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
