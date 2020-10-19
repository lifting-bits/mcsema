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
#include <memory>
#include <string>

struct Parent {
 protected:
  std::string name;

 public:
  Parent(const std::string &str) : name(str) {
    std::cout << "Parent is setting name!" << std::endl;
  }

  virtual ~Parent() = default;

  virtual void shout() = 0;
};

struct Angry : Parent {
 protected:
  int age = 42;

 public:
  Angry(const std::string &str) : Parent(str) {
    std::cout << "Angry person was born" << std::endl;
  }

  void shout() override {
    std::cout << "I am angry! I am: " << name << std::endl;
  }
};

struct Calm : Parent {
  Calm(const std::string &str) : Parent(str) {
    std::cout << "Calm person was born" << std::endl;
  }

  void shout() override {
    std::cout << "Me calm. Me: " << name << std::endl;
  }
};

int main() {
  Calm a("Caleb");
  Parent *oldMan = new Angry("Ivan");

  // This is the troublesome one
  oldMan->shout();

  std::cout << "And so shout happened" << std::endl;
  delete oldMan;
  std::cout << "Story is now over" << std::endl;
}
