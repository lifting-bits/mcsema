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

#include <utility>

#include <mcsema/CFG/Init.h>
#include <mcsema/CFG/Types.h>
#include <mcsema/CFG/Util.h>

#include <mcsema/CFG/sqlCFG.h>
#include <mcsema/CFG/Schema.h>

namespace mcsema {
namespace cfg {

template< typename Concrete = SymtabEntry >
struct SymtabEntry_ : id_based_ops_< SymtabEntry_< Concrete > >,
                      all_< SymtabEntry_< Concrete > > {
  static constexpr Query table_name = R"(symtabs)";
  Database _db;

  constexpr static Query q_insert =
    R"(insert into symtabs(name, module_rowid, type_rowid) values (?1, ?2, ?3))";

};

struct MemoryRange_ : id_based_ops_< MemoryRange_ >,
                      all_ < MemoryRange_ > {

  static constexpr Query table_name = R"(memory_ranges)";
  Database _db;

  constexpr static Query q_insert =
      R"(insert into memory_ranges(module_rowid, ea, size, bytes)
      values (?1, ?2, ?3, ?4))";
};

template< typename Self >
struct module_ops_mixin : id_based_ops_< Self >,
                          all_ < Self > {};

template< typename Concrete = Module >
struct Module_ : module_ops_mixin< Module_< Concrete > > {

  static constexpr Query table_name = R"(modules)";
  Database _db;

  Module_( Database db ) : _db( db ) {}

  constexpr static Query q_insert =
    R"(insert into modules(name) values (?1))";

};

template< typename Self >
struct func_ops_mixin :
  func_ops_< Self >,
  all_< Self >,
  id_based_ops_< Self >
{};


template< typename Concrete = Function >
struct Function_ : func_ops_mixin< Function_< Concrete > >
{
  static constexpr Query table_name = R"(functions)";
  Database _db;

  Function_() = default;
  Function_( Database db ) : _db( db ) {}

  auto insert(int64_t module_id, int64_t ea, bool is_entrypoint )
  {
    constexpr static Query q_insert =
      R"(insert into functions(module_rowid, ea, is_entrypoint) values (?1, ?2, ?3))";
    _db.template query< q_insert >( module_id, ea, is_entrypoint);
    return this->last_rowid();
  }

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
struct BasicBlock_: bb_mixin< BasicBlock_< Concrete > >
{
  Database _db;
  constexpr static Query table_name = R"(blocks)";

  BasicBlock_() = default;
  BasicBlock_( Database db ) : _db( db ) {}

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
    _db.template query<q_data>(id)(data_view);
    return std::move(data_view);
  }
};

template< typename Concrete = Segment >
struct Segment_ : id_based_ops_< Segment_< Concrete > > {
  Database _db;
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
    _db.template query<q_data>(id)(data_view);
    return std::move(data_view);
  }

  void SetFlags(int64_t id, const Segment::Flags &flags) {
    constexpr static Query q_set_flags =
      R"(UPDATE segments SET
        (read_only, is_external, is_exported, is_thread_local) =
        (?2, ?3, ?4, ?5) WHERE rowid = ?1)";
    _db.template query<q_set_flags>(id,
                                    flags.read_only, flags.is_external,
                                    flags.is_exported, flags.is_thread_local);
  }
};

struct Letter::Letter_impl
{
  Database _db;

};

/* Letter */
Letter::Letter() : impl( new Letter_impl ) {}

Letter::~Letter()
{
  delete impl;
}



void Letter::CreateSchema()
{
  Schema::CreateSchema( impl->_db );
}

Module Letter::module(const std::string &name) {
  return { Module_{ impl->_db }.insert(name) };
}

Function Letter::func(const Module &module, int64_t ea, bool is_entrypoint)
{
  return { Function_{ impl->_db }.insert(module.id, ea, is_entrypoint) };
}

BasicBlock Letter::bb(const Module &module,
                      int64_t ea,
                      int64_t size,
                      const MemoryRange &range)
{
  return { BasicBlock_{ impl->_db }.insert(module.id, ea, size, range.id) };
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   int64_t ea,
                                   int64_t size,
                                   std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{}.insert(module.id, ea, size,
                                 sqlite::blob( data.begin(), data.end() ) ) };
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   int64_t ea,
                                   std::string_view data) {
  return AddMemoryRange(module, ea, data.size(), data);
}

/* Module */

Function Module::AddFunction(int64_t ea, bool is_entrypoint ) {
  return { Function_{}.insert( id, ea, is_entrypoint ) };
}

MemoryRange Module::AddMemoryRange(int64_t ea, int64_t size, std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{}.insert(id, ea, size,
                                 sqlite::blob( data.begin(), data.end() ) ) };
}

MemoryRange Module::AddMemoryRange(int64_t ea, std::string_view data) {
  return AddMemoryRange(ea, data.size(), data);
}

BasicBlock Module::AddBasicBlock(int64_t ea, int64_t size, const MemoryRange &mem) {
  return { BasicBlock_{}.insert(id, ea, size, mem.id) };
}

SymtabEntry Module::AddSymtabEntry(const std::string &name, SymtabEntry::Type type) {
  return SymtabEntry_{}.insert(id, name, static_cast<unsigned char>(type));
}


/* Function */

void Function::AttachBlock(const BasicBlock &bb) {
  Function_<Function>{}.bind_bb(id, bb.id);
}

/* BasicBlock */
std::string BasicBlock::Data() {
    return BasicBlock_{}.data(id);
}


/* Segment */

std::string Segment::Data() {
  return Segment_{}.data(id);
}

void Segment::SetFlags(const Flags &flags) {
  return Segment_{}.SetFlags(id, flags);
}



/* MemoryRange */

Segment MemoryRange::AddSegment(int64_t ea,
                                 int64_t size,
                                 const Segment::Flags &flags,
                                 const std::string &name) {
  return Segment_{}._insert( ea, size, flags, name, id );
}


} // namespace cfg
} // namespace mcsema
