#include <iostream>
#include <string>

template< typename F >
struct Holder {
    F a;
    F b;
};

int foo( std::string str ) {
    std::cout << "Foo: " << str << std::endl;
    return 1;
}

int boo( std::string str ) {
    std::cout << "Boo: " << str << std::endl;
    return 2;
}

int main() {
    Holder< int(*)(std::string) > h { foo, boo };
    int a;
    std::cin >> a;
    if ( a % 2 ) h.a( "hello" );
    else h.b( "world" );
}
