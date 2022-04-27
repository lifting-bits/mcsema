/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdexcept>

struct ThrowOnFirstCreation {
  static int counter;

  ThrowOnFirstCreation() {
    if (!counter) {
      ++counter;
      throw std::runtime_error("Counter was zero!");
    }
  }
};

int ThrowOnFirstCreation::counter = 0;

void CreateStaticVar(ThrowOnFirstCreation **ptr) {
  if (!*ptr) {
    *ptr = new ThrowOnFirstCreation();
    return;
  }
  puts("Trying to create, ptr was not null.");
}


void StaticVarTest() {
  static ThrowOnFirstCreation* ptr = NULL;

  // This should throw an exception and ptr should remain NULL
  try {
    CreateStaticVar(&ptr);
  } catch(...) {
    puts("It did not succeed on first try");
  }

  if (ptr) {
    puts("Ptr is not NULL, error!");
  }

  // Allocates and constructs object at *ptr correctly
  try {
    CreateStaticVar(&ptr);
  } catch(...) {
    puts("It did not succeed on second try");
  }

  // Checks if it was allocated properly
  if (ptr) {
    puts("But it did succeed eventually");
    delete ptr;
  } else {
    puts("Ptr was null!");
  }
}

int main(int argc, char *argv[]) {
  puts("Throw while creating static variable\n");
  StaticVarTest();
  puts("End of test");
}
