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
         func_ea integer,
         bb_ea integer,
         FOREIGN KEY(func_ea) REFERENCES functions(ea),
         FOREIGN KEY(bb_ea) REFERENCES blocks(ea)
        ))";
    db.template query< q_func_2_block >();
  }

  static void CreateSchema(Database &db) {
    CreateEnums(db);

    static Query c_module_meta =
      R"(create table if not exists module_meta(
         name text,
         arch text,
         os text))";
    db.template query<c_module_meta>();

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

    static Query functions = R"(create table if not exists functions(
          ea integer,
          is_entrypoint integer,
          name text
          ))";
    db.template query<functions>();

    static Query blocks = R"(create table if not exists blocks(
          ea integer PRIMARY KEY NOT NULL,
          bytes blob
          ))";
    db.template query<blocks>();

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

template< typename Self >
struct _exec_mixin {

  template< const auto &q, typename ...Args >
  auto exec( Args ...args )
  {
    auto self = static_cast< const Self* >( this );
    return self._db.template query< q >( args... );
  }

};

// Second template is to avoid DDD( Dreadful Diamond of Derivation ) without using
// virtual inheritance. Since this is strictly mixin inheritance it is okay
template< typename Self, template< typename > class Derived >
struct _crtp
{
  Self &self() { return static_cast< Self & >( *this ); }
  const Self &self() const { return static_cast< const Self & >( *this ); }
};

template< typename Self >
struct all_ : _crtp< Self, all_ >
{
  static std::string _q_all()
  {
    return std::string{ "select * from " } + Self::table_name;
  }

  auto all()
  {
    return this->self()._db.template query< _q_all >();
  }

};

template< typename Self >
struct ea_based_ops_: _crtp< Self, ea_based_ops_ >
{
  static std::string _q_get()
  {
    return std::string{ "select * from " } + Self::table_name + " where ea = ?1";
  }

  auto get( uint64_t ea )
  {
    return this->self()._db.template query< _q_get >( ea );
  }

  static std::string _q_remove( uint64_t ea )
  {
    return std::string{ "delete from " } + Self::table_name + " where ea = ?1";
  }

  auto erase( uint64_t ea )
  {
    return this->self()._db.template query< _q_remove >( ea );
  }

};

template< typename Self >
struct concrete_ea_based_ops_ : ea_based_ops_< Self >
{
  using _parent = ea_based_ops_< Self >;

  auto get() { return _parent::get( this->self().ea ); }
  auto erase() { return _parent::erase( this->self().ea ); }

};

// Forward-declare concrete
template< const auto &db_name >
struct ConcreteFunc;

template< const auto &db_name >
struct ConcreteBB;

template< typename Self >
struct func_ops_ : _crtp< Self, func_ops_ >
{

  using parent_ = _crtp< Self, func_ops_ >;
  using parent_::self;

  auto bbs( uint64_t ea )
  {
    constexpr static Query q_bbs =

      R"(select * from blocks inner join func_to_block on
            blocks.ea = func_to_block.bb_ea and func_to_block.func_ea = ?1)";
    return this->self()._db.template query< q_bbs >( ea );
  }

  template < typename Container = std::vector< uint64_t > >
  auto unbind_bbs( uint64_t ea, const Container &to_unbind)
  {
    constexpr static Query q_unbind_bbs =
      R"(delete from func_to_block where func_ea = ?1 and bb_ea = ?2 )";
    for ( auto &other : to_unbind )
      this->self()._db.template query< q_unbind_bbs >( ea, other );
  }

  template< typename Container = std::vector< uint64_t > >
  auto bind_bbs( uint64_t ea, const Container &to_bind )
  {
    constexpr static Query q_bind_bbs =
      R"(insert into func_to_block values (?1, ?2))";
    for ( auto &other : to_bind )
      this->self()._db.template query< q_bind_bbs >( ea, other );

  }

};

template< typename Self >
struct concrete_func_ops_: func_ops_< Self >
{
  using parent_ = func_ops_< Self >;
  using parent_::self;

  auto bbs() { this->parent_::bbs( self().ea ); }

  template < typename Container = std::vector< uint64_t > >
  auto unbind_bbs( const Container &to_unbind)
  {
    this->parent_::unbind_bbs( self().ea, to_unbind );
  }

  template< typename Container = std::vector< uint64_t > >
  auto bind_bbs( const Container &to_bind )
  {
    this->parent_::bind_bbs( self().ea, to_bind );
  }

};


template< typename Self >
struct func_ops_mixin :
  func_ops_< Self >,
  all_< Self >,
  ea_based_ops_< Self >
{};

template< typename Self >
struct concrete_func_ops_mixin :
  concrete_func_ops_< Self >,
  all_< Self >,
  concrete_ea_based_ops_< Self >
{};

template< const auto &db_name, typename Concrete = ConcreteFunc< db_name > >
struct Func : func_ops_mixin< Func< db_name, Concrete > >
{
  static constexpr Query table_name = R"(functions)";
  sqlite::Database< db_name > _db;

  Concrete insert_bare( uint64_t ea, bool is_entrypoint, const std::string &name )
  {
    constexpr static Query q_insert_bare =
      R"(insert into functions values (?1, ?2, ?3))";
    _db.template query< q_insert_bare >( ea, is_entrypoint, name );
    return Concrete{ ea };
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
    return &Func::print;
  }

  static void print( uint64_t ea, bool is_entrypoint, const std::string &name )
  {
    std::cerr << ea << " " << is_entrypoint << " " << name << std::endl;
  }

};

template< const auto &db_name >
struct ConcreteFunc : concrete_func_ops_mixin< ConcreteFunc< db_name > >
{
  static constexpr Query table_name = R"(functions)";
  sqlite::Database< db_name > _db;
  uint64_t ea;

  ConcreteFunc( uint64_t address ) : ea( address ) {}
};

template< typename Self >
struct bb_ops_ : _crtp< Self, bb_ops_ >
{
  template< typename Data >
  auto insert( uint64_t ea, Data &&bytes )
  {
    constexpr static Query q_insert = R"(insert into blocks values (?1, ?2))";
    return this->self()._db.template query< q_insert >( ea, bytes );
  }

};

template< typename Self >
struct bb_mixin : bb_ops_< Self >,
                  ea_based_ops_< Self >,
                  all_< Self > {};

template< typename Self >
struct concrete_bb_mixin : concrete_ea_based_ops_< Self >,
                            all_< Self > {};


template< const auto &db_name, typename Concrete = ConcreteBB< db_name > >
struct bb_ops : bb_mixin< bb_ops< db_name, Concrete > >
{
  sqlite::Database< db_name > _db;
  constexpr static Query table_name = R"(blocks)";

};


template< const auto &db_name >
struct ConcreteBB : concrete_bb_mixin< ConcreteBB< db_name > >
{
  uint64_t ea;
  sqlite::Database< db_name > _db;
  constexpr static Query table_name = R"(blocks)";
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

  auto func()
  {
    return Func< db_name >{};
  }

  auto bb()
  {
    return bb_ops< db_name >();
  }

  template< typename Data >
  auto add_bb( uint64_t ea, Data &&bytes )
  {
    return bb_ops< db_name >{}.insert( ea, std::forward< Data >( bytes ) );
  }

};


} // namespace cfg
} // namespace mcsema
