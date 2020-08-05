/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
#include <assert.h>
#include <stdio.h>

int x = 0, y = 0;

#define CTOR(I) __attribute__((constructor(I))) void ct ## I() { assert( x == I - 1 ); ++x; }

__attribute__((constructor(0))) void ct_first() { assert( x == 0 ); }
CTOR( 1 );
CTOR( 2 );
CTOR( 3 );
__attribute__((constructor)) void ct_outOfOrder() { ++y; }
CTOR( 4 );

int main() {
    assert( x == 4 );
    assert( y == 1 );
}

#define DTOR(I) __attribute__((destructor(I))) void dt ## I() { assert( x == I ); --x; }

DTOR( 4 );
DTOR( 3 );
DTOR( 2 );
DTOR( 1 );

__attribute__((destructor(0))) void dt_last() {
    assert( x == 0 );
    assert( y == 1 );
    putchar( 'a' );
}
