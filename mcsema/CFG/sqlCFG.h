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

#include <iostream>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <mcsema/CFG/Iterator.h>

namespace mcsema {
namespace cfg {

// Forward-declare concrete
class Function;
class ExternalFunction;
class BasicBlock;
class Module;
class MemoryRange;
class Segment;
class SymtabEntry;
class CodeXref;
class DataXref;

// Context that represents the file and other helper data part of internal implemenation
class Context;

namespace details {
  using CtxPtr = std::shared_ptr<Context>;
} // namespace details

/* Enums */
enum class SymtabEntryType : unsigned char {
  Imported = 1, // Names from another object file
  Exported = 2, // Externally visible
  Internal = 3, // Internal
  Artificial = 4 }; // Made up by person that inserts it


// Corresponds to llvm calling convention numbering
enum class CC : unsigned char { C = 0,
                                X86_StdCall = 64,
                                X86_FastCall = 65,
                                X86_64_SysV = 78,
                                Win64 = 79
};

enum class OperandType : unsigned char {
  Immediate = 0,
  Memory = 1,
  MemoryDisplacement = 2,
  ControlFlow = 3,
  OffsetTable = 4
};

enum class FixupKind : unsigned char {
  Absolute = 0,
  OffsetFromThreadBase = 1
};



// Each object can implement some of the following interfaces
namespace interface {

  template<typename Self>
  struct HasEa {
    int64_t ea();

    // TODO: Can this be hidden away?
    template<typename HasCtx>
    static std::optional<Self> MatchEa(const HasCtx &has_ctx, int64_t ea) {
      return MatchEa(has_ctx._ctx, ea);
    }

  private:
    static std::optional<Self> MatchEa(details::CtxPtr &ctx_ptr, int64_t ea);
  };

  // Defition uses SymtabEntry class, therefore can be found lower
  template<typename Self>
  struct HasSymtabEntry;
} // namespace interface


// Internal stuff that could not be hidden away in .cpp file, plese pretend it is not here
namespace details {

class Internals {

protected:
  Internals(int64_t id, CtxPtr &ctx) : _id(id), _ctx(ctx) {}

  int64_t _id;
  mutable CtxPtr _ctx;

  friend class interface::HasSymtabEntry<CodeXref>;
  friend class interface::HasSymtabEntry<ExternalFunction>;

  friend class interface::HasEa<DataXref>;
  friend class interface::HasSymtabEntry<DataXref>;

  friend class interface::HasEa<MemoryRange>;

  friend class interface::HasEa<BasicBlock>;

  friend class interface::HasEa<Function>;
  friend class interface::HasSymtabEntry<Function>;

  friend class interface::HasEa<Segment>;
  friend class interface::HasSymtabEntry<Segment>;
};

} // namespace details


/* Each of the following objects is rather opaque and typically correspond to some
 * "object" in binaries. Some are abstract (BasicBlock, Segment, Function) but other
 * can be verbatim copies of data (for example MemoryRange).
 *
 * Even thought they do not share any general interface in their inheritance, they have
 * some similar features:
 *
 *   -> data_t is returned by operator*() and encapsulates almost all important
 *      information stored about the object, for those not included there are separate
 *      getters.
 *   -> TODO: Erase/ReplaceWith
 */


// Represent Symbol (name). It does not have to come from any binary (user can name
// things as desired with Artificial type to signify that they do not origin
// from the  binary)
class SymtabEntry : public details::Internals {
public:

  struct Data_ {
    std::string name;
    SymtabEntryType type;
  };

  using data_t = Data_;

  data_t operator*() const;

  void Erase();

private:
  friend class Module;
  friend class Function;
  friend class CodeXref;
  friend class DataXref;
  friend class Segment;
  friend class BasicBlock;

  using details::Internals::Internals;

};


namespace interface {

  // Some objects can (sometimes it is not required!) have name -- this interface
  // allows manipulation with it
  template<typename Self>
  struct HasSymtabEntry {
    std::optional<std::string> Name();
    void Name(const SymtabEntry& name);
    std::optional<SymtabEntry::data_t> Symbol();
  };

} // namespace interface


class ExternalFunction : public details::Internals,
                         public interface::HasEa<ExternalFunction>,
                         public interface::HasSymtabEntry<ExternalFunction> {
public:

  struct Data_ {
    int64_t ea;
    CC cc;
    bool has_return;
    bool weak;
  };

  using data_t = Data_;
  data_t operator*() const;

  std::string Name() const;

  void Erase();

private:
  friend class Module;
  friend class interface::HasEa<ExternalFunction>;

  using details::Internals::Internals;
};

class BasicBlock : public details::Internals,
                   public interface::HasEa<BasicBlock> {
public:

    // We are not including underlying data, since they are being cached and need
    // separate query anyway
    struct Data_ {
      int64_t ea;
      int64_t size;
    };

    using data_t = Data_;
    data_t operator*() const;

    // Cached
    std::string_view Data();

    CodeXref AddXref(int64_t ea, int64_t target_ea, OperandType op_type);
    CodeXref AddXref(int64_t ea,
                     int64_t target_ea,
                     OperandType op_type,
                     const SymtabEntry &name,
                     std::optional<int64_t> mask={});

    void AddSucc(const BasicBlock &bb);

    template<typename Collection = std::vector<BasicBlock>>
    void AddSuccs(const Collection &bbs) {
      for (auto bb : bbs) {
        AddSucc(bb);
      }
    }

    void RemoveSucc(const BasicBlock &bb);
    void RemoveSuccs();

    WeakObjectIterator<BasicBlock> Succs();

    WeakObjectIterator<CodeXref> CodeXrefs();
    WeakDataIterator<CodeXref> CodeXrefs_d();

    void Erase();
private:

  friend class Function;
  friend class Letter;
  friend class Module;
  friend details::ObjectIterator_impl;
  friend interface::HasEa<BasicBlock>;

  using details::Internals::Internals;
};


class Function : public details::Internals,
                 public interface::HasEa<Function>,
                 public interface::HasSymtabEntry<Function> {

public:

  struct Data_ {
    int64_t ea;
    bool is_entrypoint;
  };
  using data_t = Data_;
  data_t operator*() const;

  void AttachBlock(const BasicBlock &bb);

  template<typename Collection = std::vector<BasicBlock>>
  void AttachBlocks(const Collection &bbs) {
    for (auto bb : bbs) {
      AttachBlock(bb);
    }
  }

  // Iterate over all attached block
  WeakObjectIterator<BasicBlock> BasicBlocks();
  // TODO: De-attach


  void Erase();

private:
  using details::Internals::Internals;

  friend class details::ObjectIterator_impl;
  friend class interface::HasEa<Function>;

  friend class Letter;
  friend class Module;
};


// Named part of some memory range
class Segment : public details::Internals,
                public interface::HasEa<Segment>,
                public interface::HasSymtabEntry<Segment> {
public:

  struct Flags {
    bool read_only;
    bool is_external;
    bool is_exported;
    bool is_thread_local;
  };

  struct Data_ {
    int64_t ea;
    int64_t size;
    // TODO: Fold this to Flags
    bool read_only;
    bool is_external;
    bool is_exported;
    bool is_thread_local;
  };

  using data_t = Data_;
  data_t operator*() const;

  // NOTE: std::string is implicitly converted to std::string_view so in case this returns
  // nonsense double check return types.
  // Cached
  std::string_view Data();
  void SetFlags(const Flags &flags);

  DataXref AddXref(int64_t ea, int64_t target_ea, int64_t width, FixupKind fixup);
  DataXref AddXref(int64_t ea, int64_t target_ea,
                   int64_t width, FixupKind fixup, const SymtabEntry &name);

  // FIXME: This does not remove xrefs, maybe add either:
  // void EraseAll()
  // or:
  // void EraseOnly()
  void Erase();


private:
  friend class MemoryRange;
  friend class Module;
  friend class Letter;

  friend class interface::HasEa<Segment>;

  using details::Internals::Internals;
};

// Verbatim copy of some data in binary
// TODO: Insert for empty like .bbs
class MemoryRange : public details::Internals,
                    public interface::HasEa<MemoryRange> {
public:

  struct Data_ {
    int64_t ea;
    int64_t range;
  };

  using data_t = Data_;
  data_t operator*() const;

  Segment AddSegment(int64_t ea,
                     int64_t size,
                     const Segment::Flags &flags,
                     const std::string &name);

  // Cached
  std::string_view Data();

  // FIXME: This does not remove Segments or BBs
  void Erase();
private:
  friend class Letter;
  friend class Module;

  friend class interface::HasEa<MemoryRange>;

  using details::Internals::Internals;
};


// Reference in some BasicBlock. It is bound to it and cannot be moved.
// If the underlying basic block is removed, reference is removed as well.
class CodeXref : public details::Internals,
                 public interface::HasEa<CodeXref>,
                 public interface::HasSymtabEntry<CodeXref> {

public:

  struct Data_ {
    int64_t ea;
    int64_t target_ea;
    OperandType op_type;
    std::optional<int64_t> mask;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const Data_ &obj) {
      os << std::hex << obj.ea << " -> " << obj.target_ea << std::dec
         << static_cast<int>(obj.op_type);
      return os;
    }
  };

  using data_t = Data_;
  data_t operator*() const;

  void Erase();

private:
  friend class Module;
  friend class BasicBlock;
  friend class interface::HasEa<CodeXref>;
  friend class interface::HasSymtabEntry<CodeXref>;
  friend class details::ObjectIterator_impl;

  using details::Internals::Internals;
};


// Reference in some Segment. It is bound to it and cannot be moved.
// If the underlying Segment if removed, reference is removed as well.
class DataXref : public details::Internals,
                 public interface::HasEa<DataXref>,
                 public interface::HasSymtabEntry<DataXref> {

public:

  struct Data_ {
    int64_t ea;
    int64_t target_ea;
    int64_t width;
    FixupKind fixup;
  };

  using data_t = Data_;
  data_t operator*() const;

  void Erase();
private:
  friend class Segment;

  friend class interface::HasEa<DataXref>;
  using details::Internals::Internals;
};

// One object file -- compiled binary or shared library for example.
class Module : public details::Internals {

public:

  Function AddFunction(int64_t ea, bool is_entrypoint);

  MemoryRange AddMemoryRange(int64_t ea, int64_t range, std::string_view data);

  MemoryRange AddMemoryRange(int64_t ea, std::string_view data);

  BasicBlock AddBasicBlock(int64_t ea, int64_t size, const MemoryRange &memory);

  SymtabEntry AddSymtabEntry(const std::string &name, SymtabEntryType type);

  ExternalFunction AddExternalFunction(int64_t ea,
                                       const SymtabEntry &name,
                                       CC cc,
                                       bool has_return, bool is_weak);

  /* Iteration */

  // Difference here is that *_d already applies operator*() on sql level,
  // which saves query per object. (This should be reasonable optimization)
  WeakDataIterator<SymtabEntry> Symbols_d();
  WeakObjectIterator<Function> Functions();

  // TODO:
  //WeakIterator<ExternalFunction> ExtFunctions();
  //WeakIterator<MemoryRange> MemoryRanges();
  //WeakIterator<Segment> Segments();

  template<typename Unary>
  void ForEachSymbol_d(Unary f) {
    for (auto weak_it = Symbols_d(); auto data = weak_it.Fetch();) {
      f(*data);
    }
  }

  // TODO: This is probably really handy if we allow Erase without removing dependent
  // objects.
  WeakObjectIterator<BasicBlock> Blocks();
  WeakObjectIterator<BasicBlock> OrphanedBasicBlocks();

  // FIXME: This should probably also delete all module-binded data?
  // void Erase();
private:
  using details::Internals::Internals;

  friend class Letter;
};


// Top-level object, encapsulates several separate object files.
struct Letter
{
  Letter(const std::string &db_name);

  void CreateSchema();

  Module AddModule(const std::string &name);

  Function AddFunction(const Module &module, int64_t ea, bool is_entrypoint);

  BasicBlock AddBasicBlock(const Module &module,
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
