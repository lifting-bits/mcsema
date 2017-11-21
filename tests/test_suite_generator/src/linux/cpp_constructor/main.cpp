/*
 * test.cpp
 *
 *  Created on: Nov 20, 2017
 *      Author: akshayk
 */

#include <cstdio>
#include <string.h>

class A {
  public:
  char name[256];

  A(const char *nameIn) {
    printf("class A constructor!\n");
    strcpy(name, nameIn);
  }

  ~A(void) {
    printf("Class A destructor!\n");
  }
};

A global("Global");

int main(void) {
  printf("Variable name %s\n", global.name);
  return 0;
}


