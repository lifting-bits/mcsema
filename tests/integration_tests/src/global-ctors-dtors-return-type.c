/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
#include <assert.h>
#include <stdio.h>

// Compiler should generate bitcast in llvm.global_ctors and llvm.global_dtors.

int x = 0, y = 0;

__attribute__((constructor(1), destructor(1))) void assert_zeroes() {
    assert( x == 0 );
    assert( y == 0 );
    putchar( 'c' );
}


__attribute__((constructor(2))) int increase_and_return() {
    ++x;
    return x;
}


__attribute__((destructor(2))) int decrease_and_return() {
    --x;
    return x;
}


int main() {
    assert( x == 1 );
    int inc_x = increase_and_return();
    assert( x == inc_x );
    int dec_x = decrease_and_return();
    assert( x == dec_x );
}
