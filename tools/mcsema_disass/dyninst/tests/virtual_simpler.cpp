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
        //Empty
    }

    void shout() override {
        std::cout << "I am angry! I am: " << name << std::endl;
    }
};

struct Calm : Parent {
    Calm( const std::string& str ) : Parent( str ) {
        //Empty
    }

    void shout() override {
        std::cout << "Me calm. Me: " << name << std::endl;
    }
};

int main() {
    Parent* oldMan = new Angry( "Ivan" );
    oldMan->shout();
    delete oldMan;

}
