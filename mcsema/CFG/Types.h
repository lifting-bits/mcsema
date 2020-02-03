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

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <mcsema/CFG/Util.h>

namespace mcsema::ws {

using Query = const char *;

// Second template is to avoid DDD(Dreadful Diamond of Derivation) without using
// virtual inheritance. Since this is strictly mixin inheritance it is okay
template<typename Self, template<typename...> class Derived>
struct _crtp
{
  Self &self() { return static_cast<Self &>(*this); }
  const Self &self() const { return static_cast<const Self &>(*this); }

  auto &db() { return self()._ctx->db; }
  auto &cache() { return self()._ctx->cache; }

  template<typename QueryResult, typename ...Ts>
  auto to_concrete(QueryResult &result) {
    return util::to_struct<Self::Concrete_t>(result.template Get<Ts...>());
  }

};

/* Objects in a binary typically share some properties (it extends to their db tables
 * as well). Following CRTP classes implement some basic behaviour that is shared for
 * many of them.
 * If some object implements operation over table, all it needs to do is inherit from
 * these and provide some basic static queries and gains a lot of wrapper code that would
 * otherwise need to be written manually.
 */


/* Requires that table has rowid as primary key */
template<typename Self>
struct id_based_ops_: _crtp<Self, id_based_ops_>
{
  using _crtp<Self, id_based_ops_>::self;

  int64_t last_rowid()
  {
    constexpr static Query q_last_row_id =
      R"(SELECT last_insert_rowid())";
    auto r = this->db().template query<q_last_row_id>();

    int64_t result;
    r(result);

    return result;
  }

  static std::string _q_get()
  {
    return std::string{ "select * from " } + Self::table_name + " where rowid = ?1";
  }

  auto get(uint64_t id)
  {
    return this->db().template query<_q_get>(id);
  }

  static std::string _q_remove()
  {
    return std::string{ "delete from " } + Self::table_name + " where rowid = ?1";
  }

  auto erase(int64_t id)
  {
    return this->db().template query<_q_remove>(id);
  }

  template<typename ...Args>
  auto insert(Args ...args) {
    this->db().template query<Self::q_insert>(args...);
    return this->last_rowid();
  }

  auto get(int64_t id) {
    return this->db().template query<Self::q_get>(id);
  }

  template<typename Concrete, typename ...Fields>
  auto maybe_c_get(int64_t id, util::TypeList<Fields...>) {
    return maybe_c_get<Concrete, Fields...>(id);
  }

  template<typename Concrete, typename ...Fields>
  auto maybe_c_get(int64_t id) {
    auto result = this->db().template query<Self::q_get>(id);
    return util::maybe_to_struct<Concrete>(*result.template Get<Fields...>());
  }

  template<typename Concrete, typename ...Fields>
  auto c_get(int64_t id, util::TypeList<Fields...>) {
    return c_get<Concrete, Fields...>(id);
  }

  template<typename Concrete, typename ...Fields>
  auto c_get(int64_t id) {
    auto result = this->db().template query<Self::q_get>(id);
    return util::to_struct<Concrete>(*result.template Get<Fields...>());
  }

  template<typename SymtabImpl>
  static std::string q_inject_symtabentry() {
    auto insert_query = std::string(SymtabImpl::s_insert_module_rowid);
    auto substitured = insert_query.replace(
        insert_query.find("#1"), 2,
        std::string("(") + Self::q_get_module_rowid + ")");
    return substitured;
  }

  template<typename SymtabImpl>
  int64_t inject_symtabentry(const std::string &name, int64_t type) {
    this->db().template query<q_inject_symtabentry<SymtabImpl>>(name, type);
    return this->last_rowid();
  }
};


/* Requires object can have symtab name and tables have symtab_rowid */
template<typename Self>
struct has_symtab_name : _crtp<Self, has_symtab_name>
{

  static std::string q_set_symtabentry() {
    return std::string{ "UPDATE " } + Self::table_name +
      " SET(symtab_rowid) = (?2) WHERE rowid = ?1";
  }

  static std::string q_get_symtabentry() {
    return std::string { "SELECT symtab_rowid FROM " } + Self::table_name +
           " WHERE rowid = ?1 and symtab_rowid NOT NULL";
  }

  static std::string q_get_name() {
    return std::string { "SELECT s.name FROM symtabs AS s JOIN "} + Self::table_name +
      " AS self ON self.rowid = ?1 and self.symtab_rowid = s.rowid";
  }

  static std::string q_get_symbol() {
    return std::string { "SELECT s.name, s.type_rowid FROM symtabs AS s JOIN "} +
      Self::table_name +
      " AS self ON self.rowid = ?1 and self.symtab_rowid = s.rowid";
  }

  auto Symbol(int64_t id) {
    return this->db().template query<q_get_symbol>(id);
  }

  auto Name(int64_t id, int64_t new_symbol_id) {
    this->db().template query<q_set_symtabentry>(id, new_symbol_id);
  }

  std::optional<int64_t> Name(int64_t id) {
    return this->db().template query<q_get_symtabentry>(id)
                     .template GetScalar<int64_t>();

  }

  std::optional<std::string> GetName(int64_t id) {
    return this->db().template query<q_get_name>(id)
                     .template GetScalar<std::string>();
  }

};

/* Requires object have ea and tables have module_rowid or override queries
 * that rely on it with some other way to get module_rowid
 */
template<typename Self>
struct has_ea : _crtp<Self, has_ea> {

  static std::string q_id_from_ea() {
    return std::string { "SELECT rowid FROM " }
        + Self::table_name
        + " WHERE ea = ?1 and module_rowid = ?2";
  }

  static std::string q_get_ea() {
    return std::string { "SELECT ea FROM " } + Self::table_name + " WHERE rowid = ?1";
  }

  static std::string q_get_module() {
    return std::string { "SELECT module_rowid FROM " } +
           + Self::table_name
           + " WHERE rowid = ?1";
  }

  uint64_t get_ea(int64_t id) {
    return this->db().template query<q_get_ea>(id)
                     .template GetScalar_r<int64_t>();
  }

  std::optional<int64_t> IdFromEa(uint64_t ea, int64_t module_id) {
    return this->db().template query<Self::q_id_from_ea>(ea, module_id)
                     .template GetScalar<int64_t>();
  }

  int64_t GetModule(int64_t id) {
    return this->db().template query<Self::q_get_module>(id)
                     .template GetScalar_r<int64_t>();
  }
};

template<typename NMTable>
struct nm_impl : _crtp<NMTable, nm_impl> {

  template<typename Self>
  static std::string q_get_others_r() {
    return std::string{ "SELECT " } + NMTable::template other<Self>::fk
           + " FROM " + NMTable::table_name
           + " WHERE " + Self::fk + " = ?1";
  }

  template<typename Self>
  static std::string q_bind() {
    return std::string{ "INSERT INTO " } + NMTable::table_name + "("
           + Self::fk + ", " + NMTable::template other<Self>::fk + ") VALUES(?1, ?2)";
  }

  template<typename Self>
  static std::string q_unbind() {
    return std::string{ "DELETE FROM " } + NMTable::table_name + " WHERE "
           + Self::fk + " = ?1";
  }

  template<typename Self>
  static std::string q_unbind_from() {
    return std::string{ "DELETE FROM " } + NMTable::table_name + " WHERE "
          + Self::fk + " = ?1 AND " + NMTable::template other<Self>::fk + " = ?2";
  }

  template<typename Self>
  auto BindTo(int64_t self_id, int64_t to_be_binded_id) {
    return this->db().template query<q_bind<Self>>(self_id, to_be_binded_id);
  }

  template<typename Self>
  auto UnbindFrom(int64_t self_id, int64_t from_id) {
    return this->db().template query<q_unbind_from<Self>>(self_id, from_id);
  }

  template<typename Self>
  auto Unbind(int64_t self_id) {
    return this->db().template query<q_unbind<Self>>(self_id);
  }

  template<typename Self>
  auto GetOthers_r(int64_t id) {
    return this->db().template query<q_get_others_r<Self>>(id);
  }

};

struct can_obj_iterate {

  template<typename Table, typename Self>
  static std::string q_get_obj_iterator() {
    return std::string { "SELECT " } + Table::pk + " FROM "
           + Table::table_name + " WHERE " + Self::fk + " = ?1";
  }

  template<typename Table, typename Self>
  static auto Get(Self &self, int64_t self_id) {
    return self.db().template query<q_get_obj_iterator<Table, Self>>(self_id);
  }

};

} // namespace mcsema::ws
