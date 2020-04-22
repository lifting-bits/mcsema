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
#include <mcsema/CFG/Enums.h>

namespace mcsema::ws {

// Forward-declare concrete
class Workspace;
class Function;
class ExternalFunction;
class BasicBlock;
class Module;
class MemoryRange;
class Segment;
class SymbolTableEntry;
class CodeXref;
class DataXref;
class MemoryLocation;
class ValueDecl;
class FuncDecl;
class PreservedRegs;

// Context that represents the file and other helper data part of internal implemenation
class Context;

using maybe_str = std::optional<std::string>;

namespace details {
  using CtxPtr = std::shared_ptr<Context>;
  struct Construct;
} // namespace details

// Each object can implement some of the following interfaces
namespace interface {

template<typename Self>
struct HasEa {
  uint64_t ea();

  // TODO: Can this be hidden away?
  // TODO: This needs to be filtered by module_id
  template<typename HasCtx>
  static std::optional<Self> MatchEa(
      const HasCtx &has_ctx,
      int64_t module_id,  // <- FIXME: normally it is private, this is ugly workaround
      uint64_t ea) {

    return MatchEa(has_ctx._ctx, module_id, ea);
  }

  // If something has ea it must be part of a module
  Module Module();

private:

  //TODO: Make this callable from outside
  static std::optional<Self> MatchEa(
      details::CtxPtr &ctx_ptr,
      int64_t module_id,
      uint64_t ea);
};

// Defition uses SymbolTableEntry class, therefore can be found lower
template<typename Self>
struct HasSymbolTableEntry;

} // namespace interface


// Internal stuff that could not be hidden away in .cpp file, plese pretend it is not here
namespace details {

class Internals {
public:

  // This is used to allow automatic meta-conversion from object of this hierarchy
  // to their ids.
  static constexpr bool is_public_api = true;

  Workspace GetWS();
protected:
  Internals(int64_t id, CtxPtr &ctx) : _id(id), _ctx(ctx) {}
  Internals(int64_t id, CtxPtr &&ctx) : _id(id), _ctx(std::move(ctx)) {}

  int64_t _id;
  mutable CtxPtr _ctx;

  friend details::Construct;

  // TODO: Do we care if someone tries to shoot in the foot really hard?
  template<typename T>
  friend class interface::HasEa;

  template<typename T>
  friend class interface::HasSymbolTableEntry;
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
class SymbolTableEntry : public details::Internals {
public:

  struct data_t {
    std::string name;
    SymbolVisibility type;
  };

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
struct HasSymbolTableEntry {
  maybe_str Name();
  void Name(const SymbolTableEntry& name);
  std::optional<SymbolTableEntry::data_t> Symbol();
};

} // namespace interface


class ExternalFunction : public details::Internals,
                         public interface::HasEa<ExternalFunction>,
                         public interface::HasSymbolTableEntry<ExternalFunction> {
public:

  struct data_t {
    uint64_t ea;
    CallingConv cc;
    bool has_return;
    bool weak;
  };

  data_t operator*() const;

  std::optional<FuncDecl> GetFuncDecl();
  void SetFuncDecl(const FuncDecl &func_decl);

  std::string Name() const;

  void Erase();

private:
  friend class Module;
  friend class interface::HasEa<ExternalFunction>;

  friend details::ObjectIterator_impl;
  using details::Internals::Internals;
};

class BasicBlock : public details::Internals,
                   public interface::HasEa<BasicBlock> {
public:

    // We are not including underlying data, since they are being cached and need
    // separate query anyway
    struct data_t {
      uint64_t ea;
      std::optional<uint64_t> size;
    };

    data_t operator*() const;

    // Cached
    std::string_view Data();

    CodeXref AddXref(uint64_t ea, uint64_t target_ea, OperandType op_type);
    CodeXref AddXref(uint64_t ea,
                     uint64_t target_ea,
                     OperandType op_type,
                     const SymbolTableEntry &name,
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
    WeakDataIterator<CodeXref> CodeXrefsData();

    void Erase();
private:

  friend class Function;
  friend class Workspace;
  friend class Module;
  friend details::ObjectIterator_impl;
  friend interface::HasEa<BasicBlock>;

  using details::Internals::Internals;
};


class Function : public details::Internals,
                 public interface::HasEa<Function>,
                 public interface::HasSymbolTableEntry<Function> {

public:

  struct data_t {
    uint64_t ea;
    bool is_entrypoint;
  };

  data_t operator*() const;

  void AttachBlock(const BasicBlock &bb);

  template<typename Collection = std::vector<BasicBlock>>
  void AttachBlocks(const Collection &bbs) {
    for (auto bb : bbs) {
      AttachBlock(bb);
    }
  }


  std::optional<FuncDecl> GetFuncDecl();
  void SetFuncDecl(const FuncDecl &func_decl);

  void DeattachBlock(const BasicBlock &bb);

  // Iterate over all attached block
  WeakObjectIterator<BasicBlock> BasicBlocks();

  void Erase();

private:
  using details::Internals::Internals;

  friend class details::ObjectIterator_impl;
  friend class interface::HasEa<Function>;

  friend class Workspace;
  friend class Module;
};


// Named part of some memory range
class Segment : public details::Internals,
                public interface::HasEa<Segment>,
                public interface::HasSymbolTableEntry<Segment> {
public:

  struct Flags {
    bool read_only;
    bool is_external;
    bool is_exported;
    bool is_thread_local;

    template<typename Stream>
    friend Stream &operator<<(Stream &os, const Flags &self) {
      os << "RO " << self.read_only << ", "
         << "External: " << self.is_external << ", "
         << "Exported: " << self.is_exported << ", "
         << "Thread local: " << self.is_thread_local;
      return os;
    }
  };

  struct data_t {
    uint64_t ea;
    uint64_t size;
    Flags flags;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const data_t &self) {
      os << std::hex << "0x" << self.ea << std::dec << " of size " << self.size
         << " and flags: " << self.flags;
      return os;
    }
  };

  data_t operator*() const;

  // NOTE: std::string is implicitly converted to std::string_view so in case this returns
  // nonsense double check return types.
  // Cached
  std::string_view Data();
  void SetFlags(const Flags &flags);

  DataXref AddXref(uint64_t ea, uint64_t target_ea, uint64_t width, FixupKind fixup);
  DataXref AddXref(uint64_t ea, uint64_t target_ea,
                   uint64_t width, FixupKind fixup, const SymbolTableEntry &name);

  // FIXME: This does not remove xrefs, maybe add either:
  // void EraseAll()
  // or:
  // void EraseOnly()
  void Erase();


private:
  friend class MemoryRange;
  friend class Module;
  friend class Workspace;

  friend class interface::HasEa<Segment>;

  friend details::ObjectIterator_impl;
  using details::Internals::Internals;
};

// Verbatim copy of some data in binary
// TODO: Insert for empty like .bbs
class MemoryRange : public details::Internals,
                    public interface::HasEa<MemoryRange> {
public:

  struct data_t {
    uint64_t ea;
    uint64_t range;
  };

  data_t operator*() const;

  Segment AddSegment(uint64_t ea,
                     uint64_t size,
                     const Segment::Flags &flags,
                     const std::string &name);

  // Cached
  std::string_view Data();

  // FIXME: This does not remove Segments or BBs
  void Erase();
private:
  friend class Workspace;
  friend class Module;

  friend class interface::HasEa<MemoryRange>;
  friend details::ObjectIterator_impl;

  using details::Internals::Internals;
};


// Reference in some BasicBlock. It is bound to it and cannot be moved.
// If the underlying basic block is removed, reference is removed as well.
class CodeXref : public details::Internals,
                 public interface::HasEa<CodeXref>,
                 public interface::HasSymbolTableEntry<CodeXref> {

public:

  struct data_t {
    uint64_t ea;
    uint64_t target_ea;
    OperandType op_type;
    std::optional<int64_t> mask;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const data_t &obj) {
      os << std::hex << obj.ea << " -> " << obj.target_ea << std::dec
         << static_cast<int>(obj.op_type);
      return os;
    }
  };

  data_t operator*() const;

  void Erase();

private:
  friend class Module;
  friend class BasicBlock;
  friend class interface::HasEa<CodeXref>;
  friend class interface::HasSymbolTableEntry<CodeXref>;
  friend class details::ObjectIterator_impl;

  using details::Internals::Internals;
};


// Reference in some Segment. It is bound to it and cannot be moved.
// If the underlying Segment if removed, reference is removed as well.
class DataXref : public details::Internals,
                 public interface::HasEa<DataXref>,
                 public interface::HasSymbolTableEntry<DataXref> {

public:

  struct data_t {
    uint64_t ea;
    uint64_t target_ea;
    uint64_t width;
    FixupKind fixup;
  };

  data_t operator*() const;

  void Erase();
private:
  friend class Segment;

  friend class interface::HasEa<DataXref>;
  using details::Internals::Internals;
};

class GlobalVar : public details::Internals,
                  public interface::HasEa<GlobalVar> {

public:
  struct data_t {
    uint64_t ea;
    std::string name;
    uint64_t size;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const data_t &self) {
      os << std::hex << "0x" << self.ea << std::dec << " of size " << self.size
         << " with name " << self.name;
      return os;
    }
  };

  data_t operator*() const;

  void Erase();

private:
  using details::Internals::Internals;

  friend details::ObjectIterator_impl;
  friend class interface::HasEa<GlobalVar>;
  friend class Module;
};

class ExternalVar : public details::Internals,
                    public interface::HasEa<ExternalVar> {
public:
  struct data_t {
    uint64_t ea;
    std::string name;
    uint64_t size;

    bool is_weak;
    bool is_thread_local;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const data_t &self) {
      os << std::hex << "0x" << self.ea << std::dec << " of size " << self.size
         << " with name " << self.name;
      return os;
    }
  };

  data_t operator*() const;
  void Erase();

private:
  using details::Internals::Internals;

  friend details::ObjectIterator_impl;
  friend class interface::HasEa<ExternalVar>;
  friend class Module;
};

class ExceptionFrame : public details::Internals {
public:

  struct data_t {
    uint64_t start_ea;
    uint64_t end_ea;
    uint64_t lp_ea;
    Action action;
  };

  data_t operator*();
  void Erase();

private:
  using details::Internals::Internals;

  friend details::ObjectIterator_impl;
  friend class Function;
};

class MemoryLocation : public details::Internals {
public:

  struct data_t {
    std::string reg;
    std::optional<int64_t> offset;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const data_t &self) {
      os << self.reg
         << ", offset: " << ((self.offset) ? std::to_string(*self.offset) : "(not set)");
      return os;
    }
  };

  data_t operator*() const;
  void Erase();

private:
  using details::Internals::Internals;

  friend class Workspace;
  friend class Module;
};

class ValueDecl : public details::Internals {
public:

  struct data_t {
    std::string type;
    maybe_str reg;
    maybe_str name;
    std::optional<MemoryLocation> mem_loc;

    template<typename Stream>
    friend Stream &operator<<(Stream &os, const data_t &self) {
      os << self.type
         <<  ", reg: " << ((self.reg) ? *self.reg : "(not set)")
         <<  ", name: " << ((self.name) ? *self.name : "(not set)") << std::endl;
      os << "mem_loc: ";
      if (self.mem_loc) {
        os << **self.mem_loc;
      } else{
        os << "(not set)";
      }
      return os;
    }
  };

  data_t operator*() const;
  void Erase();

private:
  using details::Internals::Internals;
  friend class Workspace;
  friend class FuncDecl;
  friend class details::Construct;
};


class FuncDecl : public details::Internals {
public:
  using ValueDecls = std::vector<ValueDecl>;
  using ValueDecl_it = WeakObjectIterator<ValueDecl>;

  struct data_t {
    ValueDecl ret_address;
    ValueDecls params;
    ValueDecls rets;
    ValueDecl return_stack_ptr;
    bool is_variadic;
    bool is_noreturn;
    CallingConv cc;

    template<typename Stream>
    friend Stream &operator<<(Stream &os, const data_t &self) {
      os << "varargs: " << self.is_variadic << ", noreturn: " << self.is_noreturn
         << ", cc: " << to_string(self.cc) << std::endl;
      os << "Ret_addr: " << *self.ret_address << std::endl;
      os << "Ret_stack_ptr" << *self.return_stack_ptr << std::endl;
      os << "Params:" << std::endl;
      for (auto &param: self.params) {
        os << "\t" << *param << std::endl;
      }

      os << "Rets:" << std::endl;
      for (auto &ret: self.rets) {
        os << "\t" << *ret << std::endl;
      }
      return os;
    }
  };

  data_t operator*() const;

  void AddParam(const ValueDecl &val_dec);
  void AddRet(const ValueDecl &val_dec);

  template<typename Container>
  void AddParams(const Container &val_decs) {
    for (auto &val_dec : val_decs) {
      AddParam(val_dec);
    }
  }

  template<typename Container>
  void AddRets(const Container &val_decs) {
    for (auto &val_dec : val_decs) {
      AddRet(val_dec);
    }
  }

private:
  using details::Internals::Internals;
  friend class Function;
  friend class ExternalFunction;
  friend class Workspace;
};

class PreservedRegs : public details::Internals {
public:
  using PreservationRange = std::pair<int64_t, std::optional<int64_t>>;
  using Ranges = std::vector<PreservationRange>;
  using Regs = std::vector<std::string>;

  struct data_t {
    bool is_alive;
    Regs regs;
    Ranges ranges;

    template<typename Stream>
    friend Stream& operator<<(Stream &os, const data_t &self) {
      os << "Alive: " << self.is_alive << std::endl;
      os << "Regs: ";
      for (auto &reg : self.regs) {
        os << reg << " ";
      }
      os << std::endl << "Ranges: ";
      for (auto &[begin, end] : self.ranges) {
        os << "[ " << begin << ", "
           << ((end) ? std::to_string(*end) : "(not set)") << " ] ";
      }
      return os;

    }
  };

  data_t operator*() const;

  void AddRanges(const Ranges &range);
  void AddRegs(const Regs &regs);

  void Erase();

private:
  using details::Internals::Internals;

  friend class Module;
  friend details::ObjectIterator_impl;
};


// One object file -- compiled binary or shared library for example.
class Module : public details::Internals {

public:
  ExternalVar AddExternalVar(uint64_t ea, const std::string &name, uint64_t size,
                             bool is_weak=false, bool is_thread_local=false);

  GlobalVar AddGlobalVar(uint64_t ea, const std::string &name, uint64_t size);

  Function AddFunction(uint64_t ea, bool is_entrypoint);

  MemoryRange AddMemoryRange(uint64_t ea, uint64_t range, std::string_view data);

  MemoryRange AddMemoryRange(uint64_t ea, std::string_view data);

  // Zero-initialized MemoryRange
  MemoryRange AddMemoryRange(uint64_t ea, uint64_t range);

  BasicBlock AddBasicBlock(uint64_t ea, std::optional<uint64_t> size, const MemoryRange &memory);

  SymbolTableEntry AddSymbolTableEntry(const std::string &name,
                                       SymbolVisibility type);

  ExternalFunction AddExternalFunction(uint64_t ea,
                                       const SymbolTableEntry &name,
                                       CallingConv cc,
                                       bool has_return, bool is_weak);

  PreservedRegs AddPreservedRegs(const PreservedRegs::Ranges &ranges,
                                 const PreservedRegs::Regs &regs,
                                 bool is_alive);

  /* Iteration */

  // Difference here is that *Data already applies operator*() on sql level,
  // which saves query per object. (This should be reasonable optimization)
  WeakDataIterator<SymbolTableEntry> SymbolsData();

  // TODO: With current architecture this is harder than it seems
  //WeakDataIterator<PreservedRegs> PreservedRegsData();

  WeakObjectIterator<Function> Functions();
  WeakObjectIterator<GlobalVar> GlobalVars();
  WeakObjectIterator<ExternalVar> ExternalVars();
  WeakObjectIterator<ExternalFunction> ExternalFuncs();
  WeakObjectIterator<MemoryRange> MemoryRanges();
  WeakObjectIterator<Segment> Segments();
  WeakObjectIterator<BasicBlock> Blocks();
  WeakObjectIterator<BasicBlock> OrphanedBasicBlocks();
  WeakObjectIterator<PreservedRegs> PreservedRegs();

  // FIXME: This should probably also delete all module-binded data?
  // void Erase();

  template<typename ...Targets>
  bool MatchEa(uint64_t ea, Targets ...targets) {
    return util::Match(*this, this->_id, ea, std::forward<Targets>(targets) ...);
  }

private:
  using details::Internals::Internals;

  friend class Workspace;
};


// Top-level object, encapsulates several separate object files.
struct Workspace
{
  Workspace(const std::string &db_name);

  void CreateSchema();

  Module AddModule(const std::string &name);

  std::optional<Module> GetModule(const std::string &name);

  Function AddFunction(const Module &module, uint64_t ea, bool is_entrypoint);

  BasicBlock AddBasicBlock(const Module &module,
                           uint64_t ea,
                           std::optional<uint64_t> size,
                           const MemoryRange &range);

  MemoryRange AddMemoryRange(const Module &module,
                             uint64_t ea,
                             uint64_t range,
                             std::string_view data);

  MemoryRange AddMemoryRange(const Module &module,
                             uint64_t ea,
                             std::string_view data);

  Segment AddSegment(const Module &module,
                     uint64_t ea,
                     uint64_t size,
                     const Segment::Flags &flags,
                     const std::string &name,
                     MemoryRange &mem);

  MemoryLocation AddMemoryLoc(const std::string &reg);
  MemoryLocation AddMemoryLoc(const std::string &reg, int64_t offset);

  ValueDecl AddValueDecl(const std::string &type,
                         maybe_str reg,
                         maybe_str name,
                         std::optional<MemoryLocation> mem_loc);

  FuncDecl AddFuncDecl(const ValueDecl &ret_address,
                       const ValueDecl &ret_stack_addr,
                       const FuncDecl::ValueDecls &params,
                       const FuncDecl::ValueDecls &rets,
                       bool is_variadic, bool is_noreturn, CallingConv cc);

private:
  friend class details::Construct;

  Workspace(std::shared_ptr<Context> c) :_ctx(std::move(c)) {}

  std::shared_ptr<Context> _ctx;
};


} // namespace mcsema::ws
