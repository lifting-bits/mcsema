#include <math.h>
#include <stdio.h>
#include <float.h>

void do_calc( float first, float second ) {
    float result = fmodf( first, second );
    printf( "%f\n", result );
    if ( fabsf( result - 0.4f ) < FLT_EPSILON ) printf( "Okay.\n" );
    else printf( "Nok.\n" );

}

int main() {
    printf( "Begin %f %i %i\n\t***\n", 123.456f, 2, 4);
    float fix = 5.4f;
    for ( float i = 0.1f; i <= 0.5f; i += 0.1f ) {
        do_calc( fix, i );
    }

}
