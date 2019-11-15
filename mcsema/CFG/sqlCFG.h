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

template< const auto &name >
struct Module {
  using db = sqlite::Database< name >;
  using Query = const char *;

  static void CreateEnums() {

    static Query action_enum = R"(create table if not exists exception_frame_actions(
          key integer PRIMARY KEY NOT NULL,
          action text NOT NULL
          ))";
    db::template query<action_enum>();

    static Query populate_action_enum =
      R"(insert into exception_frame_actions values(?1, ?2))";
    db::template query<populate_action_enum>(0, "Cleanup");
    db::template query<populate_action_enum>(1, "Catch");

    static Query cc = R"(create table if not exists calling_conventions(
          key integer PRIMARY KEY NOT NULL,
          calling_convention text NOT NULL
          ))";
    db::template query<cc>();

    static Query populate_cc = R"(insert into calling_conventions values(?1, ?2))";
    db::template query<populate_cc>(0, "CallerCleanup");
    db::template query<populate_cc>(1, "CalleeCleanup");
    db::template query<populate_cc>(2, "FastCall");

    static Query operand_types = R"(create table if not exists operand_types(
        key PRIMARY KEY NOT NULL,
        type text
        ))";
    db::template query<operand_types>();

    static Query populate_operad_types = R"(insert into operand_types values(?1, ?2))";
    db::template query<populate_operad_types>(0, "Immediate operand");
    db::template query<populate_operad_types>(1, "Memory operand");
    db::template query<populate_operad_types>(2, "MemoryDisplacement operand");
    db::template query<populate_operad_types>(3, "ControlFlow operand");
    db::template query<populate_operad_types>(4, "OffsetTable operand");


    static Query locations = R"(create table if not exists locations(
          key integer PRIMARY KEY NOT NULL,
          location text NOT NULL
          ))";
    db::template query<locations>();

    static Query populate_locations = R"(insert into locations values(?1, ?2))";
    db::template query<populate_locations>(0, "Internal");
    db::template query<populate_locations>(1, "External");

  }

  static void CreateNMTables()
  {
    static Query q_func_2_block =
      R"(create table if not exists func_to_block(
         func_ea integer,
         bb_ea integer,
         FOREIGN KEY(func_ea) REFERENCES functions(ea),
         FOREIGN KEY(bb_ea) REFERENCES blocks(ea)
        ))";
    db::template query< q_func_2_block >();
  }

  static void CreateScheme() {
    CreateEnums();

    static Query c_module_meta =
      R"(create table if not exists module_meta(
         name text,
         arch text,
         os text))";
    db::template query<c_module_meta>();

    static Query g_vars = R"(create table if not exists global_variables(
          ea integer,
          name text,
          size integer))";
    db::template query<g_vars>();

    static Query vars = R"(create table if not exists variables(
          ea integer,
          name text))";
    db::template query<vars>();

    static Query segments = R"(create table if not exists segments(
          ea integer,
          data blob,
          read_only integer,
          is_external integer,
          is_exported integer,
          is_thread_local integer,
          variable_name text
          ))";
    db::template query<segments>();

    static Query stack_vars = R"(create table if not exists stack_variables(
          name text,
          size integer,
          sp_offset integer,
          has_frame integer,
          reg_name text
          ))";
    db::template query<stack_vars>();

    static Query exception_frames = R"(create table if not exists exception_frames(
          func_ea integer,
          start_ea integer,
          end_ea integer,
          lp_ea integer,
          action NOT NULL REFERENCES exception_frame_actions(key)
          ))";
    db::template query<exception_frames>();

    static Query external_vars = R"(create table if not exists external_variables(
          ea integer,
          name text,
          size integer,
          is_weak integer,
          is_thread_local integer
          ))";
    db::template query<external_vars>();

    static Query external_functions = R"(create table if not exists external_functions(
          ea integer,
          name text,
          cc NOT NULL REFERENCES calling_conventions(key),
          has_return integer,
          is_weak integer,
          signature text
          ))";
    db::template query<external_functions>();

    static Query functions = R"(create table if not exists functions(
          ea integer,
          is_entrypoint integer,
          name text
          ))";
    db::template query<functions>();

    static Query blocks = R"(create table if not exists blocks(
          ea integer PRIMARY KEY NOT NULL,
          bytes blob
          ))";
    db::template query<blocks>();

    static Query code_xrefs = R"(create table if not exists code_references(
          ea integer,
          target_type NOT NULL REFERENCES operand_types(key),
          location NOT NULL REFERENCES locations(key),
          mask integer,
          name text
          ))";
    db::template query<code_xrefs>();

    CreateNMTables();
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
struct get_ea_ : _crtp< Self, get_ea_ >
{
  static std::string _q_get()
  {
    return std::string{ "select * from " } + Self::table_name + " where ea = ?1";
  }

  auto get( uint64_t ea )
  {
    return this->self()._db.template query< _q_get >( ea );
  }

};

template< typename Self >
struct ea_primary_key_ : get_ea_< Self >, all_< Self > {};

// Forward-declare
template< const auto &db_name >
struct concrete_func;

template< const auto &db_name, typename Concrete = concrete_func< db_name > >
struct func_ops : ea_primary_key_< func_ops< db_name > >
{
  sqlite::Database< db_name > _db;

  static constexpr Query table_name = R"(functions)";

  Concrete insert_bare( uint64_t ea, bool is_entrypoint, const std::string &name )
  {
    constexpr static Query q_insert_bare =
      R"(insert into functions values (?1, ?2, ?3))";
    _db.template query< q_insert_bare >( ea, is_entrypoint, name );
    return Concrete{ ea };
  }

  auto bbs( uint64_t ea )
  {
    constexpr static Query q_bbs =

      R"(select * from blocks inner join func_to_block on
            blocks.ea = func_to_block.bb_ea and func_to_block.func_ea = ?1)";
    return _db.template query< q_bbs >( ea );
  }

  template < typename Container = std::vector< uint64_t > >
  auto unbind_bbs( uint64_t self, const Container &to_unbind)
  {
    constexpr static Query q_unbind_bbs =
      R"(delete from func_to_block where func_ea = ?1 and bb_ea = ?2 )";
    for ( auto &other : to_unbind )
      _db.template query< q_unbind_bbs >( self, other );
  }

  template< typename Container = std::vector< uint64_t > >
  auto bind_bbs( uint64_t self, const Container &to_bind )
  {
    constexpr static Query q_bind_bbs =
      R"(insert into func_to_block values (?1, ?2))";
    for ( auto &other : to_bind )
      _db.template query< q_bind_bbs >( self, other );

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
    return &func_ops::print;
  }

  static void print( uint64_t ea, bool is_entrypoint, const std::string &name )
  {
    std::cerr << ea << " " << is_entrypoint << " " << name << std::endl;
  }

};

template < const auto &db_name >
struct concrete_func : func_ops< db_name >
{
  using ops = func_ops< db_name >;

  uint64_t _ea;

  concrete_func( uint64_t ea ) : _ea( ea ) {}

  template< typename QResult >
  static auto construct( QResult r )
  {
    typename ops::bare col;
    r( col.ea, col.is_entrypoint, col.name );
    return concrete_func{ col.ea };
  }

  template< typename Container = std::vector< uint64_t > >
  auto bind_bbs( const Container &to_bind )
  {
    return this->ops::bind_bbs( _ea, to_bind );
  }

  template < typename Container = std::vector< uint64_t > >
  auto unbind_bbs( const Container &to_unbind)
  {
    return this->ops::unbind_bbs( _ea, to_unbind );
  }

  auto bbs() { return bbs( _ea ); }

};


template< const auto &db_name >
struct bb_ops : ea_primary_key_< bb_ops< db_name > >
{
  sqlite::Database< db_name > _db;

  constexpr static Query table_name = R"(blocks)";

  constexpr static Query q_insert = R"(insert into blocks values (?1, ?2))";
  constexpr static Query q_fetch = R"(select * from blocks where ea = ?1)";

  template< typename Data >
  auto insert( uint64_t ea, Data &&bytes )
  {
    return _db.template query< q_insert >( ea, bytes );
  }

  template< typename DB >
  static auto fetch( DB db, uint64_t ea )
  {
    return db.query< q_fetch >( ea );
  }

  auto get( uint64_t ea )
  {
    static Query q_get = R"(select * from blocks where ea = ?1)";
    return exec< q_get >( ea );
  }

  template< const auto &q, typename ...Args >
  auto exec( Args ...args) {
    return _db.template query< q >(args...);
  }

};

template< const auto &db_name >
struct Letter_
{
  sqlite::Database< db_name > _db;


  void create_scheme()
  {
    Module<db_name>::CreateScheme();
  }

  auto func()
  {
    return func_ops< db_name >();
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
