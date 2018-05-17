#include <stdio.h>
#include <stdlib.h>
#include <iostream>

template< typename FuncPtr, typename Num = int >
int specialSum( Num* arr, int size, FuncPtr ptr, int base = 0 ) {
    int result = base;
    for ( int i = 0; i < size; ++i ) {
        result = ptr( result, arr[i] );
    }
    return result;
}


int add( int a, int b ) {
    return a + b;
}

int dec( int a, int b ) {
    return a - 1;
} 

int joker( int a, int b ) {
    if ( a > b ) return dec ( a, b );
    if ( a < b ) return add ( a, b );
    return 0;
}

template< typename ordFunc, typename getFunc >
auto specialFunc( ordFunc ord, getFunc get, int input ) {
    int salt = 42;

    auto g = get( input, salt );
    int arr[3] = { input, salt, g };
    
    if ( specialSum( arr, 3, ord) > 0 ) return add;
    else return dec;
}

int main( int argc, char* argv[] ) {
    int arr[10] = { 1, 4, 32, -54, 5, 6, 76, 12, 45, -89 };
    int res = specialSum( arr, 10, add );
    printf( "%i\n", res );

    res = specialSum( arr, 10, dec );
    printf( "%i\n", res );

    res = specialSum( arr, 10, joker );
    printf( "%i\n", res );

    auto special = specialFunc( add, dec, std::stoi( argv[1] ) );
    printf( "%i\n", special( 37, 5 ) );
}
