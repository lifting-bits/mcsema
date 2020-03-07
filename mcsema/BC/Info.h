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

#pragma once

#include <iostream>
#include <string>

namespace llvm {
class Function;
} // namespace llvm

namespace mcsema::info {

struct Kinds {
  // TODO(lukas): std::string_view once c++17 is available
  static constexpr char *ea_kind = "bin.ea";
  static constexpr char *name_kind = "bin.name";
};

struct Info {
  std::string name;
  uint64_t ea;

  template<typename Stream>
  friend Stream &operator<<(Stream &os, const Info &info) {
    os << "0x" << std::hex << info.ea << std::dec << ": " << info.name << std::endl;
    return os;
  }
};

void Set(const Info &meta, llvm::Function &func);
Info Get(llvm::Function &func);

std::string Name(llvm::Function &func);
uint64_t EA(llvm::Function &func);

} // namespace mcsema::info


