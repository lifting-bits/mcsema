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

#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace mcsema {
namespace cfg {

// Forward-declare concrete
class Function;
class BasicBlock;
class Module;
class MemoryRange;
class Segment;
class SymtabEntry;

// Context that represents the file and other helper data part of internal implemenation
class Context;

namespace details {

using CtxPtr = std::shared_ptr<Context>;
class Internals {

protected:
  Internals(int64_t id, CtxPtr &ctx) : _id(id), _ctx(ctx) {}

  int64_t _id;
  mutable CtxPtr _ctx;

};

} // details

class SymtabEntry : details::Internals {
public:

  enum class Type : unsigned char { Imported = 1, // TODO:
                                    Exported = 2, // Externally visible
                                    Internal = 3, // Internal
                                    Artificial = 4 }; // Not from module

private:
  friend class Module;

  using details::Internals::Internals;
};

class Module : details::Internals {

public:

  Function AddFunction(int64_t ea, bool is_entrypoint);

  MemoryRange AddMemoryRange(int64_t ea, int64_t range, std::string_view data);

  MemoryRange AddMemoryRange(int64_t ea, std::string_view data);

  BasicBlock AddBasicBlock(int64_t ea, int64_t size, const MemoryRange &memory);

  SymtabEntry AddSymtabEntry(const std::string &name, SymtabEntry::Type type);

private:
  using details::Internals::Internals;

  friend class Letter;
};


class BasicBlock : details::Internals {
public:

    std::string Data();

private:

  friend class Function;
  friend class Letter;
  friend class Module;

  using details::Internals::Internals;
};


class Function : details::Internals {

public:
  void AttachBlock(const BasicBlock &bb);

  template<typename Collection = std::vector<BasicBlock>>
  void AttachBlocks(const Collection &bbs) {
    for (auto bb : bbs) {
      AttachBlock(bb);
    }
  }

  Function &Name(const SymtabEntry &entry);
  std::optional<SymtabEntry> Name();

private:
  using details::Internals::Internals;

  friend class Letter;
  friend class Module;
};

class Segment : details::Internals {
public:

  struct Flags {
    bool read_only;
    bool is_external;
    bool is_exported;
    bool is_thread_local;
  };

  // TODO: Cache and return std::string_view
  // NOTE: std::string is implicitly converted to std::string_view so in case this returns
  // nonsense double check return types.
  std::string Data();
  void SetFlags(const Flags &flags);

private:
  friend class MemoryRange;
  friend class Module;
  friend class Letter;

  using details::Internals::Internals;
};

// TODO: Insert for empty like .bbs
class MemoryRange : details::Internals {
public:
  Segment AddSegment(int64_t ea,
                     int64_t size,
                     const Segment::Flags &flags,
                     const std::string &name);

private:
  friend class Letter;
  friend class Module;

  using details::Internals::Internals;
};


struct Letter
{
  Letter(const std::string &db_name);

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

  MemoryRange AddMemoryRange(const Module &module,
                             int64_t ea,
                             std::string_view data);





  Segment AddSegment(const Module &module,
                     int64_t ea,
                     int64_t size,
                     const Segment::Flags &flags,
                     const std::string &name,
                     MemoryRange &mem);

private:
  std::shared_ptr<Context> _ctx;
};


} // namespace cfg
} // namespace mcsema
