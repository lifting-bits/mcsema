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

#pragma once

#include <utility>
#include <vector>

#include "mcsema/CFG/SQLiteWrapper.h"

namespace mcsema {
namespace cfg {

// Forward-declare concrete
class Function;
class BasicBlock;
class Module;
class MemoryRange;

class Module {

public:

  Function AddFunction(int64_t ea, bool is_entrypoint);

  MemoryRange AddMemoryRange(int64_t ea, int64_t range, std::string_view data);

  BasicBlock AddBasicBlock(int64_t ea, int64_t size, const MemoryRange &memory);

private:
  Module(int64_t rowid) : id( rowid ) {}

  int64_t id;

  friend class Letter;
};


class BasicBlock {

private:
  BasicBlock(int64_t rowid) : id(rowid) {}

  int64_t id;

  friend class Function;
  friend class Letter;
  friend class Module;
};


class Function {

public:
  void AttachBlock(const BasicBlock &bb);

  template<typename Collection = std::vector<BasicBlock>>
  void AttachBlocks(const Collection &bbs) {
    for (auto bb : bbs) {
      AttachBlock(bb);
    }
  }

private:
  Function(int64_t rowid) : id( rowid ) {}

  int64_t id;

  friend class Letter;
  friend class Module;
};

// TODO: Insert for empty like .bbs
class MemoryRange {

private:
  friend class Letter;
  friend class Module;

  MemoryRange(int64_t rowid) : id( rowid ) {}

  int64_t id;

};


struct Letter
{
  Letter();
  ~Letter();

  void CreateSchema();

  Module module(const std::string &name);

  Function func(const Module &module, int64_t ea, bool is_entrypoint);

  BasicBlock bb(const Module &module,
                int64_t ea,
                int64_t size,
                const MemoryRange &range);

  MemoryRange AddMemoryRange(const Module &module,
                             int64_t ea,
                             int64_t range,
                             std::string_view data);
private:

  struct Letter_impl;
  Letter_impl *impl;

};


} // namespace cfg
} // namespace mcsema
