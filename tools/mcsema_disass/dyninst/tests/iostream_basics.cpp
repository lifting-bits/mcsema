#include <iostream>

struct A {
    std::string value;
    
    A( std::string&& str ) : value( std::move( str ) ) {
        std::cout << "I was stolen from!:" << str << std::endl;
    }

    void shout() {
        std::cout << value << std::endl;
    }
};

int main() {
    std::cout << "Hello World!" << std::endl;
    std::string precious = "My little precious";
    A a( std::move( precious ) );
    a.shout();
}
