#include <iostream>
#include <string>

struct A {
    std::string message;

    void shout( const std::string& target ) {
        std::cout << "He shouted at " << target << " with this words:" << std::endl;
        std::cout << "\t" << message << std::endl;
    }
};

void challenge( A*& a ) {
    a = new A( { "How dare you touch my duck?" } );
    std::cout << "INFO: challenge is prepared" << std::endl;
}

int main() {
    A* ptr;
    challenge( ptr );
    ptr->shout( "Ivan" );
    delete ptr;
}
