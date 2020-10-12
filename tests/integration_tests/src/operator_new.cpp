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
#include <string>

struct A {
  std::string message;

  void shout(const std::string &target) {
    std::cout << "He shouted at " << target << " with this words:" << std::endl;
    std::cout << "\t" << message << std::endl;
  }
};

void challenge(A *&a) {
  a = new A({"How dare you touch my duck?"});
  std::cout << "INFO: challenge is prepared" << std::endl;
}

int main() {
  A *ptr;
  challenge(ptr);
  ptr->shout("Ivan");
  delete ptr;
}
