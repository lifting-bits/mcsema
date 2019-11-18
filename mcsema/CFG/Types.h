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

namespace mcsema::cfg {

using Query = const char *;

// Second template is to avoid DDD( Dreadful Diamond of Derivation ) without using
// virtual inheritance. Since this is strictly mixin inheritance it is okay
template< typename Self, template< typename > class Derived >
struct _crtp
{
  Self &self() { return static_cast< Self & >( *this ); }
  const Self &self() const { return static_cast< const Self & >( *this ); }
};

template< typename Self >
struct id_based_ops_: _crtp< Self, id_based_ops_ >
{
  int64_t last_rowid()
  {
    constexpr static Query q_last_row_id =
      R"(SELECT last_insert_rowid())";
    auto r = this->self()._db.template query< q_last_row_id >();

    int64_t result;
    r( result );

    return result;
  }

  static std::string _q_get()
  {
    return std::string{ "select * from " } + Self::table_name + " where id = ?1";
  }

  auto get( uint64_t id )
  {
    return this->self()._db.template query< _q_get >( id );
  }

  static std::string _q_remove( uint64_t ea )
  {
    return std::string{ "delete from " } + Self::table_name + " where id = ?1";
  }

  auto erase( uint64_t id )
  {
    return this->self()._db.template query< _q_remove >( id );
  }

};

template< typename Self >
struct concrete_id_based_ops_ : id_based_ops_< Self >
{
  using _parent = id_based_ops_< Self >;

  auto get() { return _parent::get( this->self().id ); }
  auto erase() { return _parent::erase( this->self().id ); }

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

  auto bind_bb( uint64_t f_id, uint64_t bb_id )
  {
    constexpr static Query q_bind_bbs =
      R"(insert into func_to_block (func_ea, bb_ea) values (?1, ?2))";
    this->self()._db.template query< q_bind_bbs >( f_id, bb_id);

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
struct bb_ops_ : _crtp< Self, bb_ops_ >
{
  template< typename Module, typename Data >
  auto insert( Module &&module, uint64_t ea, uint64_t size, Data &&bytes )
  {
    constexpr static Query q_insert =
      R"(insert into blocks(module, ea, size, bytes) values (?1, ?2, ?3, ?4))";
    return this->self()._db.template query< q_insert >( module.id, ea, size, bytes );
  }

};


} // namespace mcsema::cfg
