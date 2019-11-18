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

#include "mcsema/CFG/SQLiteWrapper.h"
#include "mcsema/CFG/Types.h"
#include "mcsema/CFG/Util.h"

namespace mcsema {
namespace cfg {

using Query = const char *;

template< auto db >
using Result_ = typename sqlite::Database< db >::QueryResult;

template< auto db >
using Database_ = sqlite::Database< db >;

template< typename Database >
struct Schema {
  using Query = const char *;

  static void CreateEnums(Database &db) {

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

  static void CreateNMTables(Database &db)
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

  static void CreateSchema(Database &db) {
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

    static Query blocks = R"(create table if not exists blocks(
          ea integer NOT NULL,
          size integer,
          bytes blob,
          module integer,
          id integer PRIMARY KEY,
          FOREIGN KEY(module) REFERENCES modules(id)
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


struct Module {

  Module(int64_t rowid) : id( rowid ) {}

  Function AddFunction(uint64_t ea, bool is_entrypoint);

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

  int64_t id;
};


Function Module::AddFunction(uint64_t ea, bool is_entrypoint ) {
  return Function_{}.insert( id, ea, is_entrypoint );
}

template< typename Self >
struct module_ops_mixin : id_based_ops_< Self >,
                          all_ < Self > {};

template< const auto &db_name, typename Concrete = Module >
struct Module_ : module_ops_mixin< Module_< db_name, Concrete > > {

  static constexpr Query table_name = R"(modules)";
  sqlite::Database< db_name > _db;

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


template< const auto &db_name, typename Concrete = Function >
struct Function_ : func_ops_mixin< Function_< db_name, Concrete > >
{
  static constexpr Query table_name = R"(functions)";
  sqlite::Database< db_name > _db;

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
    return &Function_<db_name, Concrete>::print;
  }

  static void print( uint64_t ea, bool is_entrypoint, const std::string &name )
  {
    std::cerr << ea << " " << is_entrypoint << " " << name << std::endl;
  }

};


template< typename Self >
struct bb_mixin : id_based_ops_< Self >,
                  all_< Self > {};

template< const auto &db_name, typename Concrete = BasicBlock >
struct BasicBlock_: bb_mixin< BasicBlock_< db_name, Concrete > >
{
  sqlite::Database< db_name > _db;
  constexpr static Query table_name = R"(blocks)";

  template< typename Module, typename Data >
  auto insert( Module &&module, uint64_t ea, uint64_t size, Data &&bytes )
  {
    constexpr static Query q_insert =
      R"(insert into blocks(module, ea, size, bytes) values (?1, ?2, ?3, ?4))";
    _db.template query< q_insert >( module.id, ea, size, bytes );
    return Concrete{ this->last_rowid() };
  }

};


template< const auto &db_name >
struct Letter_
{
  sqlite::Database< db_name > _db;
  using dbT = sqlite::Database< db_name >;

  void CreateSchema()
  {
    Schema<dbT>::CreateSchema( _db );
  }

  Module module(const std::string &name) {
    return Module_< db_name >{}.insert(name);
  }

  Function func(Module module, uint64_t ea, bool is_entrypoint)
  {
    return Function_< db_name >{}.insert(module, ea, is_entrypoint);
  }

  BasicBlock bb(Module module, uint64_t ea, uint64_t range, std::string_view data)
  {
    return BasicBlock_< db_name >{}.insert(module, ea, range, data);
  }

};


} // namespace cfg
} // namespace mcsema
