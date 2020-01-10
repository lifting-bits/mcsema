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
#include <type_traits>

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

void do_some_special_throwing(int val) {
  if (val == 42) {
    puts("Random float is thrown");
    throw 4.22f;
  }
  do_some_throwing(val);
}


#define Ook_def(type) void Ook(const type &err) { \
  puts("Ook " #type); \
}

#define Continue_def(type) void continue_print(const type &err) { \
  puts("Continue handler for " #type); \
}

#define Continue_branch(head, type) \
  if (std::is_same<head, type>::value) { \
    puts("Continuing catcher of " #type); \
  }

Ook_def(float)
Ook_def(std::runtime_error)
Ook_def(std::out_of_range)
Ook_def(CustomException)
Ook_def(int)
Ook_def(Empty)
Ook_def(std::exception)

template <class Head, class ... Tail>
struct TestRunner {
  static void run(int val) {
    try {
      TestRunner<Tail ...>::run(val);
    } catch (Head err) {
      Ook(err);
    }

    Continue_branch(Head, float)
    else Continue_branch(Head, std::out_of_range)
    else Continue_branch(Head, std::runtime_error)
    else Continue_branch(Head, int)
    else Continue_branch(Head, CustomException)
    else Continue_branch(Head, std::exception)
    else Continue_branch(Head, Empty)
  }
};

template<typename T>
struct TestRunner<T> {
  static void run(int val) {
    try {
      do_some_special_throwing(val);
    } catch (T err) {
      Ook(err);
    }
  }
};

template<typename ...Args>
void RunGeneratedSequences() {
  for (int i = 40; i < 50; ++i) {
    TestRunner<Args...>::run(i);
    puts("\n");
  }
}

void GeneratedSequences() {
  puts("*** Next sequence");
  RunGeneratedSequences<
    std::out_of_range, std::runtime_error, int, CustomException, float>();

  puts("*** Next sequence");
  RunGeneratedSequences<
    std::out_of_range, std::runtime_error, int, float, CustomException>();

  puts("*** Next sequence");
  RunGeneratedSequences<
    std::runtime_error, std::out_of_range, std::exception, int, float, CustomException>();
}

int main(int argc, char *argv[]) {
  puts("Generated sequences\n");
  GeneratedSequences();
  puts("End of test");
}
