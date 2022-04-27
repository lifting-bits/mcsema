/* TAGS: min cpp exceptions */
/* CC_OPTS: -std=c++14 */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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
#include <stdlib.h>
#include <iostream>
#include <stdexcept>

#define CATCH(type, status) catch(type err) { \
  puts(#type"  was caught " status); \
  }

struct CustomException {
  char inner_state[128] = "abcdefgh\0";

  CustomException(char c) {
    inner_state[0] = c;
  }

  const char *what() {
    puts("My inner state is:");
    puts(inner_state);
    return inner_state;
  }

  char state() const {
    return inner_state[0];
  }
};

void ThrowRuntime() {
  puts("Throwing runtime_error");
  throw std::runtime_error("runtime_error");
}

void ThrowOutOfRange() {
  puts("Throwing out_of_range");
  throw std::out_of_range("out_of_range");
}

void ThrowInt(int a) {
  puts("Throwing int");
  throw a;
}

void ThrowCustom(char c) {
  puts("Throwing custom");
  throw CustomException(c);
}

void SimpleException() {
  try {
    ThrowRuntime();
  } CATCH(std::runtime_error, "OK")

  try {
    ThrowOutOfRange();
  } CATCH(std::runtime_error, "NOK")
    CATCH(std::out_of_range, "OK")

  try {
    ThrowInt(42);
  } CATCH(std::runtime_error, "NOK")
    CATCH(std::out_of_range, "NOK")
  catch (int a) {
    if (a != 42) {
      puts("Incorrect integer was caught!");
    } else {
      puts("Correct in was caught!");
    }
  }

  try {
    ThrowCustom('m');
  } CATCH(std::runtime_error, "NOK")
    CATCH(std::out_of_range, "NOK")
    CATCH(int, "NOK")
    CATCH(CustomException, "OK")
}

int main(int argc, char *argv[]) {
  puts("Simple exceptions being thrown\n");
  SimpleException();
  puts("End of test");
}
