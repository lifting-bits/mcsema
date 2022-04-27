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
#include <stdexcept>

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

struct Empty {};

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

void do_some_throwing(int val) {
  int decider = val % 4;
  switch (decider) {
    case 0: ThrowRuntime();
    case 1: ThrowOutOfRange();
    case 2: ThrowInt(val);
    case 3: ThrowCustom(val);
  }
}


void MoreComplexExceptions_impl(int iter, int &val) {
  puts("MoreComplexExceptions_impl\n");
  int arr[10] = { 0, iter - 2, 2, 3, iter + 3, 5, 6, 7, iter, 9 };
  for (int i = 0; i < iter; ++i) {
    val += arr[i];
  }
  try {
    do_some_throwing(val);
  } catch (...) {
    puts("Caught something");
    printf("val is %i\n", val);
  }
  if (iter) {
    MoreComplexExceptions_impl(iter - 1, val);
  }
}

void MoreComplexExceptions() {
  int original_val_location = 0;
  MoreComplexExceptions_impl(10, original_val_location);
}

int main(int argc, char *argv[]) {
  puts("More complex call chain\n");
  MoreComplexExceptions();
  puts("End of test");

}
