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

#include <type_traits>
#include <unordered_map>

namespace mcsema::cfg {
// FIXME: This could inherit from sqlite::Database, but is it worth it?
template<typename DB>
struct Base {
  DB &db;

  Base( DB &db_) : db(db_) {}
};


template<typename Table, typename Data, typename Key, typename Next>
struct Cache : Next {

  using Next::Next;

  using Key_t = Key;
  using Table_t = Table;
  using Data_t = Data;

  std::unordered_map<Key_t, Data> cache;

  #define ENABLE_IF(ret) \
    std::enable_if_t<std::is_same_v<Table_, Table_t>, ret>

  template< typename Table_, const auto &query_str>
  auto Find(Key_t id) -> ENABLE_IF(std::string_view) {
    auto entry = cache.find(id);

    if (entry == cache.end()) {
      return Fetch<Table_, query_str>(std::move(id));
    }
    return { entry->second };
  }

  template<typename Table_, const auto &query_str>
  auto Fetch(Key_t id) -> ENABLE_IF(std::string_view) {
    auto data = Next::db.template query<query_str>(id)
                        .template GetScalar<Data_t>();
    if (!data)
      return {};
    auto [it, _] = cache.insert( { std::move(id), std::move(*data) } );
    return { it->second };
  }

  template<typename Table_>
  auto Evict(Key_t id) -> ENABLE_IF(void) {
    cache.erase(std::move(id));
  }

  #undef ENABLE_IF
};

class MemoryRange;
template<typename DB>
using MemoryRangeCache = Cache<MemoryRange, std::string, int64_t, Base<DB>>;

} // namespace mcsema::cfg
