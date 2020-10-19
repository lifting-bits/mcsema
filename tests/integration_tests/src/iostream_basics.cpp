/* TAGS: min cpp */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
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

struct A {
  std::string value;

  A(std::string &&str) : value(std::move(str)) {
    std::cout << "I was stolen from!:" << str << std::endl;
  }

  void shout() {
    std::cout << value << std::endl;
  }
};

int main() {
  std::cout << "Hello World!" << std::endl;
  std::string precious = "My little precious";
  A a(std::move(precious));
  a.shout();
}
