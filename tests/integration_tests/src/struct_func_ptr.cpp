/* TAGS: min cpp */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: */
/* STDIN: 4\n4\n */
/* TEST: */
/* STDIN: 5\n5\n */
/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <iostream>
#include <string>

template <typename F>
struct Holder {
  F a;
  F b;
};

int foo(std::string str) {
  std::cout << "Foo: " << str << std::endl;
  return 1;
}

int boo(std::string str) {
  std::cout << "Boo: " << str << std::endl;
  return 2;
}

int main() {
  Holder<int (*)(std::string)> h{foo, boo};
  int a;
  std::cin >> a;
  if (a % 2)
    h.a("hello");
  else
    h.b("world");
}
