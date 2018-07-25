#include <memory>
#include <string>
#include <iostream>

struct Parent {
protected:
    std::string name;
public:
    Parent( const std::string& str ) : name( str ) {
        std::cout << "Parent is setting name!" << std::endl;
    }

    virtual ~Parent() = default;

    virtual void shout() = 0;
};

struct Angry : Parent {
protected:
    int age = 42;
public:
    Angry( const std::string& str ) : Parent( str ) {
        std::cout << "Angry person was born" << std::endl;
    }

    void shout() override {
        std::cout << "I am angry! I am: " << name << std::endl;
    }
};

struct Calm : Parent {
    Calm( const std::string& str ) : Parent( str ) {
        std::cout << "Calm person was born" << std::endl;
    }

    void shout() override {
        std::cout << "Me calm. Me: " << name << std::endl;
    }
};

int main() {
    Calm a( "Caleb" );
    Parent* oldMan = new Angry( "Ivan" );
    
    // This is the troublesome one
    oldMan->shout();
    
    std::cout << "And so shout happened" << std::endl;
    delete oldMan;
    std::cout << "Story is now over" << std::endl;
}
