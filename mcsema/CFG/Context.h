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

#include <mcsema/CFG/Cache.h>
#include <mcsema/CFG/SQLiteWrapper.h>

#include <string>

namespace mcsema::ws {

using Query = const char *;

// TODO: Allow some other names as well
static inline std::string Name() {
  return "example.sql";
}

// General context every object of front API has. Handles db and cache.
class Context {
 public:
  Context(const std::string &db_name) : _db_name(db_name), db(db_name) {}

  using DB_t = sqlite::Database;
  using Result_t = sqlite::QueryResult;
  std::string _db_name;
  DB_t db;
  mcsema::ws::MemoryRangeCache<DB_t> cache = (db);
};

}  // namespace mcsema::ws
