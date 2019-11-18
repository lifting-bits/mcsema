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

#include "mcsema/CFG/SQLiteWrapper.h"
#include "mcsema/CFG/Types.h"
#include "mcsema/CFG/Util.h"

#include "mcsema/CFG/sqlCFG.h"

namespace mcsema {
namespace cfg {

using Query = const char *;
std::string _db_name = "example.sql";
using Database = sqlite::Database< _db_name >;

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

  }

  template< typename Database >
  static void CreateNMTables(Database db)
  {
    static Query q_func_2_block =
      R"(create table if not exists func_to_block(
         func_ea integer NOT NULL,
         bb_ea integer NOT NULL,
         FOREIGN KEY(func_ea) REFERENCES functions(ea),
         FOREIGN KEY(bb_ea) REFERENCES blocks(ea)
        ))";
    db.template query< q_func_2_block >();
  }

  template< typename Database >
  static void CreateSchema(Database db) {
    CreateEnums(db);

    static Query c_module =
      R"(create table if not exists modules(
         name text,
         id integer PRIMARY KEY
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
          module integer,
          id integer PRIMARY KEY,
          FOREIGN KEY(module) REFERENCES modules(id)
          ))";
    db.template query<functions>();

    static Query memory_ranges = R"(create table if not exists memory_ranges(
      ea integer NOT NULL,
      size integer,
      module integer,
      bytes blob,
      id integer PRIMARY KEY,
      FOREIGN KEY(module) REFERENCES modules(id)
    ))";

    db.template query<memory_ranges>();

    static Query blocks = R"(create table if not exists blocks(
          ea integer NOT NULL,
          size integer,
          module integer,
          memory integer,
          id integer PRIMARY KEY,
          FOREIGN KEY(module) REFERENCES modules(id),
          FOREIGN KEY(memory) REFERENCES memory_ranges(id)
          ))";
    db.template query<blocks>();



    static Query g_vars = R"(create table if not exists global_variables(
          ea integer,
          name text,
          size integer))";
    db.template query<g_vars>();

    static Query vars = R"(create table if not exists variables(
          ea integer,
          name text))";
    db.template query<vars>();

    static Query segments = R"(create table if not exists segments(
          ea integer,
          data blob,
          read_only integer,
          is_external integer,
          is_exported integer,
          is_thread_local integer,
          variable_name text
          ))";
    db.template query<segments>();

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

// Forward-declare concrete
struct Function;
struct BasicBlock;
struct Module;
struct MemoryRange;



template< typename Concrete = MemoryRange >
struct MemoryRange_ : id_based_ops_< MemoryRange_< Concrete > >,
                      all_ < MemoryRange_< Concrete > > {

  static constexpr Query table_name = R"(memory_ranges)";
  Database _db;


  Concrete insert(const Module &module,
                  uint64_t ea,
                  uint64_t size,
                  std::string_view data)
  {
    constexpr static Query q_insert =
      R"(insert into memory_ranges(ea, size, module, bytes) values (?1, ?2, ?3, ?4))";
    _db.template query<q_insert>(ea, size, module.id, data.data());
    return Concrete{ this->last_rowid() };
  }
};


template< typename Self >
struct module_ops_mixin : id_based_ops_< Self >,
                          all_ < Self > {};

template< typename Concrete = Module >
struct Module_ : module_ops_mixin< Module_< Concrete > > {

  static constexpr Query table_name = R"(modules)";
  Database _db;

  Module_( Database db ) : _db( db ) {}

  Concrete insert(const std::string &name) {
     constexpr static Query q_insert =
       R"(insert into modules(name) values (?1))";
     _db.template query<q_insert>(name);
     return Concrete{ this->last_rowid() };
  }

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

  Concrete insert(
      Module module, uint64_t ea, bool is_entrypoint )
  {
    constexpr static Query q_insert =
      R"(insert into functions(module, ea, is_entrypoint) values (?1, ?2, ?3))";
    _db.template query< q_insert >( module.id, ea, is_entrypoint);
    return Concrete{ this->last_rowid() };
  }

  struct bare
  {
    uint64_t ea;
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

  static void print( uint64_t ea, bool is_entrypoint, const std::string &name )
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

  auto insert( const Module &module, uint64_t ea, uint64_t size, const MemoryRange &mem)
  {
    constexpr static Query q_insert =
      R"(insert into blocks(module, ea, size, memory) values (?1, ?2, ?3, ?4))";
    _db.template query< q_insert >( module.id, ea, size, mem.id );
    return Concrete{ this->last_rowid() };
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
  return Module_{ impl->_db }.insert(name);
}

Function Letter::func(const Module &module, uint64_t ea, bool is_entrypoint)
{
  return Function_{ impl->_db }.insert(module, ea, is_entrypoint);
}

BasicBlock Letter::bb(const Module &module,
                      uint64_t ea,
                      uint64_t size,
                      const MemoryRange &range)
{
  return BasicBlock_{ impl->_db }.insert(module, ea, size, range);
}

MemoryRange Letter::AddMemoryRange(const Module &module,
                                   uint64_t ea,
                                   uint64_t size,
                                   std::string_view data) {
  return MemoryRange_{}.insert(module.id, ea, size, data);
}

/* Module */

Function Module::AddFunction(uint64_t ea, bool is_entrypoint ) {
  return Function_{}.insert( id, ea, is_entrypoint );
}

MemoryRange Module::AddMemoryRange(uint64_t ea, uint64_t size, std::string_view data) {
  return MemoryRange_{}.insert(id, ea, size, data);
}

BasicBlock Module::AddBasicBlock(uint64_t ea, uint64_t size, const MemoryRange &mem) {
  return BasicBlock_{}.insert(id, ea, size, mem.id);
}

/* Function */

void Function::BindBBs(const std::vector<BasicBlock> &bbs) {
  // TODO: Can this be done smarter?
  auto dispatch = Function_{};
  for ( auto &bb : bbs ) {
    dispatch.bind_bb(id, bb.id);
  }
}

void Function::BindBB(const BasicBlock &bb) {
  Function_<Function>{}.bind_bb(id, bb.id);
}

} // namespace cfg
} // namespace mcsema
