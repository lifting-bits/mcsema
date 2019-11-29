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

#include <memory>
#include <utility>

#include <mcsema/CFG/Types.h>
#include <mcsema/CFG/Util.h>

#include <mcsema/CFG/sqlCFG.h>
#include <mcsema/CFG/Schema.h>
#include <mcsema/CFG/Context.h>

namespace mcsema {
namespace cfg {

using Database = decltype(Context::db);

using CtxPtr = std::shared_ptr<Context>;
using CtxR = Context *;

template<typename Ctx>
struct with_context {

  with_context(CtxPtr &shared_ctx) : _ctx(shared_ctx.get()) {}

  CtxR _ctx;
};

using has_context = with_context< Context >;

template< typename Concrete = SymtabEntry >
struct SymtabEntry_ : has_context,
                      id_based_ops_< SymtabEntry_< Concrete > >,
                      all_< SymtabEntry_< Concrete > > {
  using has_context::has_context;
  static constexpr Query table_name = R"(symtabs)";

  constexpr static Query q_insert =
    R"(insert into symtabs(name, module_rowid, type_rowid) values (?1, ?2, ?3))";

  constexpr static Query q_get =
    R"(select name, type_rowid from symtabs where rowid = ?1)";

};

struct MemoryRange_ : has_context,
                      id_based_ops_< MemoryRange_ >,
                      all_ < MemoryRange_ > {

  using has_context::has_context;
  static constexpr Query table_name = R"(memory_ranges)";

  constexpr static Query q_insert =
      R"(insert into memory_ranges(module_rowid, ea, size, bytes)
      values (?1, ?2, ?3, ?4))";
};

template< typename Self >
struct module_ops_mixin : id_based_ops_< Self >,
                          all_ < Self > {};

template< typename Concrete = Module >
struct Module_ : has_context,
                 module_ops_mixin< Module_< Concrete > > {

  using has_context::has_context;
  static constexpr Query table_name = R"(modules)";

  constexpr static Query q_insert =
    R"(insert into modules(name) values (?1))";

};

template< typename Self >
struct func_ops_mixin :
  func_ops_< Self >,
  all_< Self >,
  id_based_ops_< Self >,
  has_symtab_name< Self >
{};


template< typename Concrete = Function >
struct Function_ : has_context,
                   func_ops_mixin< Function_< Concrete > >
{
  using has_context::has_context;
  static constexpr Query table_name = R"(functions)";
  static constexpr Query q_insert =
      R"(insert into functions(module_rowid, ea, is_entrypoint) values (?1, ?2, ?3))";

  struct bare
  {
    int64_t ea;
    bool is_entrypoint;
    std::string name;
  };

  template< typename R, typename Yield >
  static void iterate( R &&r, Yield yield )
  {
    bare _values;
    return util::iterate(
        std::forward< R >( r ), yield,
        _values.ea, _values.is_entrypoint, _values.name );
  }

  auto print_f()
  {
    return &Function_< Concrete>::print;
  }

  static void print( int64_t ea, bool is_entrypoint, const std::string &name )
  {
    std::cerr << ea << " " << is_entrypoint << " " << name << std::endl;
  }

};


template< typename Self >
struct bb_mixin : id_based_ops_< Self >,
                  all_< Self > {};

template< typename Concrete = BasicBlock >
struct BasicBlock_: has_context,
                    bb_mixin< BasicBlock_< Concrete > >
{
  using has_context::has_context;
  constexpr static Query table_name = R"(blocks)";

  constexpr static Query q_insert =
    R"(insert into blocks(module_rowid, ea, size, memory_rowid)
        values (?1, ?2, ?3, ?4))";

  std::string data(int64_t id) {
    // SUBSTR index starts from 0, therefore we need + 1
    constexpr static Query q_data =
      R"(SELECT SUBSTR(mr.bytes, bb.ea - mr.ea + 1) FROM
          blocks as bb JOIN
          memory_ranges as mr ON
          mr.rowid = bb.memory_rowid and bb.rowid = ?1)";
    sqlite::blob data_view;
    _ctx->db.template query<q_data>(id)(data_view);
    return std::move(data_view);
  }
};

template< typename Concrete = Segment >
struct Segment_ : has_context,
                  id_based_ops_< Segment_< Concrete > > {
  using has_context::has_context;
  constexpr static Query table_name = R"(segments)";

  Segment_() = default;

  constexpr static Query q_insert =
    R"(insert into segments(
        ea, size,
        read_only, is_external, is_exported, is_thread_local,
        variable_name, memory_rowid) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8))";

  auto _insert(int64_t ea,
               int64_t size,
               const Segment::Flags &flags,
               const std::string &name,
               int64_t memory_rowid) {

    return this->insert(ea, size,
                        flags.read_only, flags.is_external, flags.is_exported,
                        flags.is_thread_local,
                        name, memory_rowid);
  }


  std::string data(int64_t id) {
    constexpr static Query q_data =
      R"(SELECT SUBSTR(mr.bytes, s.ea - mr.ea + 1, s.size) FROM
          segments as s JOIN
          memory_ranges as mr ON
          mr.rowid = s.memory_rowid and s.rowid = ?1)";
    sqlite::blob data_view;
    this->db().template query<q_data>(id)(data_view);
    return std::move(data_view);
  }

  void SetFlags(int64_t id, const Segment::Flags &flags) {
    constexpr static Query q_set_flags =
      R"(UPDATE segments SET
        (read_only, is_external, is_exported, is_thread_local) =
        (?2, ?3, ?4, ?5) WHERE rowid = ?1)";
    this->db().template query<q_set_flags>(id,
                                    flags.read_only, flags.is_external,
                                    flags.is_exported, flags.is_thread_local);
  }
};

/* Letter */

Letter::Letter(const std::string &name) : _ctx(std::make_shared<Context>(name)) {}

void Letter::CreateSchema()
{
  Schema::CreateSchema( *_ctx );
}

Module Letter::module(const std::string &name) {
  return { Module_{ _ctx }.insert(name), _ctx };
}

Function Letter::func(const Module &module, int64_t ea, bool is_entrypoint)
{
  return { Function_{ _ctx }.insert(module._id, ea, is_entrypoint), _ctx };
}

BasicBlock Letter::bb(const Module &module,
                      int64_t ea,
                      int64_t size,
                      const MemoryRange &range)
{
  return { BasicBlock_{ _ctx }.insert(module._id, ea, size, range._id), _ctx };
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   int64_t ea,
                                   int64_t size,
                                   std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{ _ctx }.insert(module._id, ea, size,
                                 sqlite::blob( data.begin(), data.end() ) ),
            _ctx };
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   int64_t ea,
                                   std::string_view data) {
  return AddMemoryRange(module, ea, data.size(), data);
}

/* Module */

Function Module::AddFunction(int64_t ea, bool is_entrypoint ) {
  return { Function_{ _ctx }.insert( _id, ea, is_entrypoint ), _ctx };
}

MemoryRange Module::AddMemoryRange(int64_t ea, int64_t size, std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{ _ctx }.insert(_id, ea, size,
                                 sqlite::blob( data.begin(), data.end() ) ),
           _ctx };
}

MemoryRange Module::AddMemoryRange(int64_t ea, std::string_view data) {
  return AddMemoryRange(ea, data.size(), data);
}

BasicBlock Module::AddBasicBlock(int64_t ea, int64_t size, const MemoryRange &mem) {
  return { BasicBlock_{ _ctx }.insert(_id, ea, size, mem._id), _ctx };
}

SymtabEntry Module::AddSymtabEntry(const std::string &name, SymtabEntry::Type type) {
  return { SymtabEntry_{ _ctx }.insert(name, _id, static_cast<unsigned char>(type)),
           _ctx };
}

/* SymtabEntry */
SymtabEntry::Data SymtabEntry::operator*() const {
  SymtabEntry::Data out;
  unsigned char a;
  SymtabEntry_{ _ctx }.get(_id)(out.name, a);
  out.type = static_cast<Type>(a);
  return out;
}



/* Function */

void Function::AttachBlock(const BasicBlock &bb) {
  Function_<Function>{ _ctx }.bind_bb(_id, bb._id);
}

Function &Function::Name(const SymtabEntry &entry) {
  Function_{ _ctx }.Name(_id, entry._id);
  return *this;
}

std::optional<SymtabEntry> Function::Name() {
  auto maybe_id = Function_{ _ctx }.Name(_id);
  if (maybe_id) {
    return { { *maybe_id, _ctx } };
  }
  return {};
}

/* BasicBlock */
std::string BasicBlock::Data() {
    return BasicBlock_{ _ctx }.data(_id);
}


/* Segment */

std::string Segment::Data() {
  return Segment_{ _ctx }.data(_id);
}

void Segment::SetFlags(const Flags &flags) {
  return Segment_{ _ctx }.SetFlags(_id, flags);
}



/* MemoryRange */

Segment MemoryRange::AddSegment(int64_t ea,
                                 int64_t size,
                                 const Segment::Flags &flags,
                                 const std::string &name) {
  return { Segment_{ _ctx }._insert( ea, size, flags, name, _id ), _ctx };
}


} // namespace cfg
} // namespace mcsema
