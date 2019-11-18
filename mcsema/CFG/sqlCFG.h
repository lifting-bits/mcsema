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
struct Function;
struct BasicBlock;
struct Module;
struct MemoryRange;

struct Module {

  Module(int64_t rowid) : id( rowid ) {}

  Function AddFunction(uint64_t ea, bool is_entrypoint);

  MemoryRange AddMemoryRange(uint64_t ea, uint64_t range, std::string_view data);

  BasicBlock AddBasicBlock(uint64_t ea, uint64_t size, const MemoryRange &memory);

  int64_t id;
};


struct BasicBlock
{
  BasicBlock(int64_t rowid) : id(rowid) {}

  int64_t id;
};


struct Function
{
  Function(int64_t rowid) : id( rowid ) {}

  void BindBB(const BasicBlock &bb);

  void BindBBs(const std::vector<BasicBlock> &bbs);

  int64_t id;
};

// TODO: Insert for empty like .bbs
struct MemoryRange
{
  MemoryRange(int64_t rowid) : id( rowid ) {}

  int64_t id;
};


struct Letter
{
  Letter();
  ~Letter();

  void CreateSchema();

  Module module(const std::string &name);

  Function func(const Module &module, uint64_t ea, bool is_entrypoint);

  BasicBlock bb(const Module &module,
                uint64_t ea,
                uint64_t size,
                const MemoryRange &range);

  MemoryRange AddMemoryRange(const Module &module,
                             uint64_t ea,
                             uint64_t range,
                             std::string_view data);

  struct Letter_impl;
  Letter_impl *impl;

};


} // namespace cfg
} // namespace mcsema
