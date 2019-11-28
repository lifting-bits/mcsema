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

#include <mcsema/CFG/Types.h>
#include <mcsema/CFG/Util.h>

#include <mcsema/CFG/sqlCFG.h>

namespace mcsema {
namespace cfg {

using Query = const char *;
std::string _db_name = "example.sql";
using Database = sqlite::Database< _db_name >;

void Init(const std::string &name) {
  _db_name = name;
}

struct Schema {

  template< typename Database >
  static void CreateEnums(Database db) {

    static Query action_enum = R"(create table if not exists exception_frame_actions(
          key integer PRIMARY KEY NOT NULL,
          action text NOT NULL
          ))";
    db.template query<action_enum>();

    static Query populate_action_enum =
      R"(insert into exception_frame_actions values(?1, ?2))";
    db.template query<populate_action_enum>(0, "Cleanup");
    db.template query<populate_action_enum>(1, "Catch");

    static Query cc = R"(create table if not exists calling_conventions(
          key integer PRIMARY KEY NOT NULL,
          calling_convention text NOT NULL
          ))";
    db.template query<cc>();

    static Query populate_cc = R"(insert into calling_conventions values(?1, ?2))";
    db.template query<populate_cc>(0, "CallerCleanup");
    db.template query<populate_cc>(1, "CalleeCleanup");
    db.template query<populate_cc>(2, "FastCall");

    static Query operand_types = R"(create table if not exists operand_types(
        key PRIMARY KEY NOT NULL,
        type text
        ))";
    db.template query<operand_types>();

    static Query populate_operad_types = R"(insert into operand_types values(?1, ?2))";
    db.template query<populate_operad_types>(0, "Immediate operand");
    db.template query<populate_operad_types>(1, "Memory operand");
    db.template query<populate_operad_types>(2, "MemoryDisplacement operand");
    db.template query<populate_operad_types>(3, "ControlFlow operand");
    db.template query<populate_operad_types>(4, "OffsetTable operand");


    static Query locations = R"(create table if not exists locations(
          key integer PRIMARY KEY NOT NULL,
          location text NOT NULL
          ))";
    db.template query<locations>();

    static Query populate_locations = R"(insert into locations values(?1, ?2))";
    db.template query<populate_locations>(0, "Internal");
    db.template query<populate_locations>(1, "External");


    static Query symtab_types = R"(create table if not exists symtab_types(
        type text NOT NULL
        ))";
    db.template query<symtab_types>();

    static Query populate_symtab_types = R"(insert into symtab_types(type) values(?1))";
    db.template query<populate_symtab_types>("internal");
    db.template query<populate_symtab_types>("external");
    db.template query<populate_symtab_types>("artificial");
    db.template query<populate_symtab_types>("exported");
  }

  template< typename Database >
  static void CreateNMTables(Database db)
  {
    static Query q_func_2_block =
      R"(create table if not exists function_to_block(
         function_rowid integer NOT NULL,
         bb_rowid integer NOT NULL,
         UNIQUE(function_rowid, bb_rowid),
         FOREIGN KEY(function_rowid) REFERENCES functions(rowid),
         FOREIGN KEY(bb_rowid) REFERENCES blocks(rowid)
        ))";
    db.template query< q_func_2_block >();
  }

  template< typename Database >
  static void CreateSchema(Database db) {
    CreateEnums(db);

    static Query c_module =
      R"(create table if not exists modules(
         name text
        ))";
    db.template query<c_module>();

    static Query c_module_meta =
      R"(create table if not exists module_meta(
         name text,
         arch text,
         os text))";
    db.template query<c_module_meta>();

    static Query functions = R"(create table if not exists functions(
          ea integer NOT NULL,
          is_entrypoint integer,
          name text,
          module_rowid integer,
          FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
          ))";
    db.template query<functions>();

    static Query memory_ranges = R"(create table if not exists memory_ranges(
      ea integer NOT NULL,
      size integer,
      module_rowid integer,
      bytes blob,
      FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
    ))";

    db.template query<memory_ranges>();

    static Query blocks = R"(create table if not exists blocks(
          ea integer NOT NULL,
          size integer,
          module_rowid integer,
          memory_rowid integer,
          FOREIGN KEY(module_rowid) REFERENCES modules(rowid),
          FOREIGN KEY(memory_rowid) REFERENCES memory_ranges(rowid)
          ))";
    db.template query<blocks>();

    static Query segments = R"(create table if not exists segments(
          ea integer NOT NULL,
          size integer,
          read_only integer,
          is_external integer,
          is_exported integer,
          is_thread_local integer,
          variable_name text,
          memory_rowid integer,
          FOREIGN KEY(memory_rowid) REFERENCES memory_ranges(rowid)
          ))";
    db.template query<segments>();

    static Query symtabs = R"(create table if not exists symtabs(
          name text NOT NULL,
          module_rowid integer NOT NULL,
          type_rowid integer NOT NULL,
          FOREIGN KEY(type_rowid) REFERENCES symtab_types(rowid),
          FOREIGN KEY(module_rowid) REFERENCES modules(rowid)
          ))";
    db.template query<symtabs>();

    // TODO: Rework/Check below

    static Query g_vars = R"(create table if not exists global_variables(
          ea integer,
          name text,
          size integer))";
    db.template query<g_vars>();

    static Query vars = R"(create table if not exists variables(
          ea integer,
          name text))";
    db.template query<vars>();

    static Query stack_vars = R"(create table if not exists stack_variables(
          name text,
          size integer,
          sp_offset integer,
          has_frame integer,
          reg_name text
          ))";
    db.template query<stack_vars>();

    static Query exception_frames = R"(create table if not exists exception_frames(
          func_ea integer,
          start_ea integer,
          end_ea integer,
          lp_ea integer,
          action NOT NULL REFERENCES exception_frame_actions(key)
          ))";
    db.template query<exception_frames>();

    static Query external_vars = R"(create table if not exists external_variables(
          ea integer,
          name text,
          size integer,
          is_weak integer,
          is_thread_local integer
          ))";
    db.template query<external_vars>();

    static Query external_functions = R"(create table if not exists external_functions(
          ea integer,
          name text,
          cc NOT NULL REFERENCES calling_conventions(key),
          has_return integer,
          is_weak integer,
          signature text
          ))";
    db.template query<external_functions>();

    static Query code_xrefs = R"(create table if not exists code_references(
          ea integer,
          target_type NOT NULL REFERENCES operand_types(key),
          location NOT NULL REFERENCES locations(key),
          mask integer,
          name text
          ))";
    db.template query<code_xrefs>();

    CreateNMTables(db);
  }

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
    constexpr static Query q_data =
      R"(SELECT SUBSTR(mr.bytes, bb.ea - mr.ea) FROM
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
      R"(SELECT SUBSTR(mr.bytes, s.ea - mr.ea, s.size) FROM
          segments as s JOIN
          memory_ranges as mr ON
          mr.rowid = s.memory_rowid)";
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

/* Module */

Function Module::AddFunction(int64_t ea, bool is_entrypoint ) {
  return { Function_{}.insert( id, ea, is_entrypoint ) };
}

MemoryRange Module::AddMemoryRange(int64_t ea, int64_t size, std::string_view data) {
  // TODO: Check if this copy to sqlite::blob is required
  return { MemoryRange_{}.insert(id, ea, size,
                                 sqlite::blob( data.begin(), data.end() ) ) };
}

BasicBlock Module::AddBasicBlock(int64_t ea, int64_t size, const MemoryRange &mem) {
  return { BasicBlock_{}.insert(id, ea, size, mem.id) };
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
