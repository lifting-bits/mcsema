#pragma once

#include <string>

#include <mcsema/CFG/SQLiteWrapper.h>

namespace mcsema::cfg {

using Query = const char *;

static inline std::string Name() {
  return "example.sql";
}

class Context {
public:
  Context(const std::string &db_name) : _db_name(db_name) {}

  std::string _db_name;
  sqlite::Database<Name> db;
};

} // namespace mcsema::cfg
