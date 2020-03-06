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

#include "sqlite3.h"

#include <array>
#include <optional>
#include <thread>
#include <mutex>
#include <iostream>
#include <vector>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <utility>

namespace sqlite {

namespace detail {

template <typename T>
inline bool dependent_false = false;

// Given a concrete function type T:
//   get_fn_info<T>::ret_type is the return type
//   get_fn_info<T>::num_args is the number of arguments to the function
//   get_fn_info<T>::arg_type<i> is the type of the i'th argument

template <typename T>
struct get_fn_info {
  static_assert(dependent_false<T>);
};

template <typename R, typename... As>
struct get_fn_info<R(*)(As...)> {
  using ret_type = R;
  using arg_types = std::tuple<As...>;
  template <unsigned i>
  using arg_type = std::tuple_element_t<i, arg_types>;
  static constexpr int num_args = std::tuple_size_v<arg_types>;
};

template <typename T>
constexpr bool is_std_optional_type = false;

template <typename T>
constexpr bool is_std_optional_type<std::optional<T>> = true;

// If THING is invocable, invoke it and return the result, otherwise return
// THING itself.
inline constexpr auto maybe_invoke = [] (auto &&thing) -> decltype(auto) {
  if constexpr (std::is_invocable_v<decltype(thing)>) {
    return thing();
  } else {
    return std::forward<decltype(thing)>(thing);
  }
};

// This mutex guards against the one-time configuration of SQLite that is
// performed before any connection is made to the database.
inline std::mutex sqlite3_config_mutex;

// This is set to true once the one-time configuration of SQLite gets
// performed.
inline bool sqlite3_configured = false;

// This is the error log callback installed by the wrapper.
//
// TODO(ppalka): Make the choice of error log callback configurable.
inline void sqlite_error_log_callback(void *, int err_code, const char *msg) {
  std::cerr << "SQLite error (" << err_code << "): " << msg << std::endl;
}

template<class T, class...Ts>
struct is_one_of : std::disjunction<std::is_same<T, Ts>...> {};

template<class T, class...Ts>
inline constexpr bool is_one_of_v = is_one_of<T, Ts...>::value;

} // namespace detail

// Define an explicit specialization `user_serialize_fn<T>` or perhaps
// `user_serialize_fn<T, std::enable_if_t<...>>` if you want to be able to pass
// objects of type `T` to `query()` invocations.  The specialization should be
// a function that takes as argument a `T` object and whose return type is one
// which is already convertible e.g. an integral type, an
// `std::optional<std::string>`, etc.

template <typename T, typename = void>
constexpr auto user_serialize_fn = nullptr;

// This explicit specialization allows binding `std::optional<T>` when `T` is a
// convertible user type.
template <typename T>
constexpr auto user_serialize_fn<std::optional<T>,
                                 std::enable_if_t<user_serialize_fn<T> != nullptr>>
  = [] (const std::optional<T> &arg) {
    return (arg ? std::make_optional(user_serialize_fn<T>(*arg))
                : std::nullopt);
  };

// Define an explicit specialization `user_deserialize_fn<T>` or perhaps
// `user_deserialize_fn<T, std::enable_if_t<...>>` if you want to be able
// convert SQLite result values to `T` objects, allowing you to pass objects of
// type `T` to QueryResult invocations.  The specialization should be a
// function whose argument type is something that we know how to convert an
// SQLite value to, and whose return type is an object of type `T`.
template <typename T, typename = void>
constexpr auto user_deserialize_fn = nullptr;


// This class behaves just like `std::string`, except that we bind values of
// this type as BLOBs rather than TEXT.
class blob : public std::string {
 public:
  template <typename... Ts>
  blob(Ts &&...args) : std::string(std::forward<Ts>(args)...) { }
};

// This class behaves just like `std::string_view`, except that we bind values
// of this type as BLOBs rather than TEXT.
class blob_view : public std::string_view {
 public:
  template <typename... Ts>
  blob_view(Ts &&...args) : std::string_view(std::forward<Ts>(args)...) { }
};

// The class of SQLite errors.  When an exceptional error is encountered, we
// throw an exception of this type.
class error : public std::exception {
 public:
  int err_code;
  error (int code) : err_code(code) { }
};

class incorrect_query : public std::runtime_error {
public:

  incorrect_query(int code_, const std::string &mssg_)
    : std::runtime_error(std::string("E") + std::to_string(code_) + ": " + mssg_)
  {}
};

namespace detail {

template <typename T>
struct decay_tuple_args {
  static_assert(dependent_false<T>);
};

template <typename... Ts>
struct decay_tuple_args<std::tuple<Ts...>> {
  using type = std::tuple<std::decay_t<Ts>...>;
};

} // namespace detail

using hook_t = void(*)(sqlite3 *);
using hooks_t = std::vector< hook_t >;

class TransactionGuard;

struct Connection {
  sqlite3 *db_handle;

  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;

  Connection(const std::string &db_name,
             const hooks_t &post_connection_hooks = {}) {
    // Since each thread has its own exclusive connection to the database, we
    // can safely set SQLITE_CONFIG_MULTITHREAD so that SQLite may assume
    // the database will not be accessed from the same connection by two
    // threads simultaneously.
    do {
      std::lock_guard<std::mutex> guard(detail::sqlite3_config_mutex);
      if (!detail::sqlite3_configured) {
        sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
        sqlite3_config(SQLITE_CONFIG_LOG,
                       detail::sqlite_error_log_callback, nullptr);
        detail::sqlite3_configured = true;
      }
    } while (0);
    auto ret = sqlite3_open(db_name.c_str(), &db_handle);
    if (ret != SQLITE_OK) {
      throw error{ret};
    }

    // When the database has been temporarily locked by another process, this
    // tells SQLite to retry the command/query until it succeeds, rather than
    // returning SQLITE_BUSY immediately.
    sqlite3_busy_handler(db_handle,
        [](void *, int) {
          std::this_thread::yield();
          return 1;
        },
        nullptr);

    for (auto &post_hook : post_connection_hooks ) {
      post_hook(db_handle);
    }
  }

  ~Connection(void) {
    // To close the database, we use sqlite3_close_v2() because unlike
    // sqlite3_close(), this function allows there to be un-finalized
    // prepared statements.  The database handle will close once
    // all prepared statements have been finalized by the thread-local
    // `PreparedStmtCache` destructors.
    sqlite3_close_v2(db_handle);
  }
};

// QueryResult corresponds to the results of a query executed by query().
// Results can be stepped through row-by-row by invoking the QueryResult
// directly.  When a QueryResult gets destroyed, the prepared statement is
// cleaned up and gets placed into the prepared-statement cache it came from
// for later reuse.
class QueryResult {
 public:
  QueryResult() = default;

  QueryResult &operator=(QueryResult &&other) {
    if (this != &other) {
      std::swap(stmt, other.stmt);
      std::swap(put_cb, other.put_cb);
      std::swap(ret, other.ret);
      std::swap(first_invocation, other.first_invocation);
    }
    return *this;
  }

  QueryResult(QueryResult &&other) {
    using std::swap;
    swap(stmt, other.stmt);
    swap(put_cb, other.put_cb);
    swap(ret, other.ret);
    swap(first_invocation, other.first_invocation);
  }

  ~QueryResult() {
    if (stmt == nullptr) {
      return;
    }
    sqlite3_clear_bindings(stmt);
    sqlite3_reset(stmt);
    put_cb(stmt);
  }

  // Returns the SQLite result code of the most recent call to sqlite3_step()
  // on the prepared statement.
  int resultCode(void) {
    return ret;
  }

  template<class Arg, int64_t idx>
  std::enable_if_t<std::is_enum_v<Arg>, Arg>
  _Get() {
    using target_t = std::underlying_type_t<Arg>;
    return static_cast<Arg>(_Get<target_t, idx>());
  }

  template<class Arg, int64_t idx>
  std::enable_if_t<detail::is_one_of_v<Arg, std::string, std::string_view>, Arg>
  _Get() {
    return { reinterpret_cast<const char*>(sqlite3_column_text(stmt, idx)),
             sqlite3_column_bytes(stmt, idx) };
  }

  template<class Arg, int64_t idx>
  std::enable_if_t<detail::is_one_of_v<Arg, sqlite::blob, sqlite::blob_view>, Arg>
  _Get() {
    return { reinterpret_cast<const char *>(sqlite3_column_blob(stmt, idx)),
             sqlite3_column_bytes(stmt, idx) };
  }

  template<class Arg, int64_t idx>
  std::enable_if_t<std::is_integral_v<Arg>, Arg>
  _Get() {
    return sqlite3_column_int64(stmt, idx);
  }

  template<class Arg, int64_t idx>
  std::enable_if_t<std::is_same_v<std::nullopt_t, Arg>, Arg>
  _Get() {
    return {};
  }

  template<class Arg, int64_t idx>
  std::enable_if_t<detail::is_std_optional_type<Arg>, Arg>
  _Get() {
    if (sqlite3_column_type(stmt, idx) == SQLITE_NULL) {
      return {};
    }
    return { _Get<typename Arg::value_type, idx>() };
  }

  template<typename ...Ts, int64_t ...indices>
  std::tuple<Ts ...> Get_helper(std::integer_sequence<int64_t, indices ...>) {
    return std::make_tuple<Ts ...>( _Get<Ts, indices>() ...);
  }

  void Step() {
    if (!first_invocation) {
      ret = sqlite3_step(stmt);
    }
    first_invocation = false;
  }

  template<typename... Ts>
  std::optional<std::tuple<Ts...>> Get() {
    if (static_cast<int>(sizeof...(Ts)) > sqlite3_column_count(stmt)) {
      throw incorrect_query{SQLITE_ERROR, "Get argument count is greater than allowed"};
    }

    Step();
    if (ret != SQLITE_ROW) {
      return {};
    }

    using seq_t = std::make_integer_sequence<int64_t, sizeof ... (Ts)>;
    return { Get_helper<Ts...>(seq_t{}) };
  }

  template<typename T>
  std::optional<T> GetScalar() {
    if (sqlite3_column_count(stmt) == 0) {
      throw incorrect_query{SQLITE_ERROR,
                            "GetScalar argument count is greater than allowed"};
    }

    Step();

    if (ret != SQLITE_ROW) {
      return {};
    }

    return { _Get<T, 0>() };
  }

  template<typename T>
  T GetScalar_r() {
    return *GetScalar<T>();
  }

  // Step through a row of results, binding the columns of the current row to
  // ARGS in order.  If there are no more rows, returns false.  Otherwise,
  // returns true.
  template <typename... Ts>
  bool operator()(Ts &&...args) {
    if (static_cast<int>(sizeof...(args)) > sqlite3_column_count(stmt)) {
      throw error{SQLITE_ERROR};
    }
    if (!first_invocation) {
      ret = sqlite3_step(stmt);
    }
    if (ret != SQLITE_ROW) {
      return false;
    }
    int idx = 0;
    auto column_dispatcher = [this, &idx] (auto &&arg, auto &self) {

      using arg_t = std::decay_t<decltype(arg)>;
      if constexpr (std::is_integral_v<arg_t>) {
        arg = sqlite3_column_int64(stmt, idx);
      } else if constexpr (std::is_same_v<std::string, arg_t> ||
                           std::is_same_v<std::string_view, arg_t>) {
        auto ptr = (const char *)sqlite3_column_text(stmt, idx);
        auto len = sqlite3_column_bytes(stmt, idx);
        arg = arg_t(ptr, len);
      } else if constexpr (std::is_same_v<sqlite::blob, arg_t> ||
                           std::is_same_v<sqlite::blob_view, arg_t>) {
        auto ptr = (const char *)sqlite3_column_blob(stmt, idx);
        auto len = sqlite3_column_bytes(stmt, idx);
        arg = arg_t(ptr, len);
      } else if constexpr (std::is_same_v<std::nullopt_t, arg_t>) {
        ;
      } else if constexpr (detail::is_std_optional_type<arg_t>) {
        if (sqlite3_column_type(stmt, idx) == SQLITE_NULL) {
          arg.reset();
        } else {
          typename arg_t::value_type nonnull_arg;
          self(nonnull_arg, self);
          arg = std::move(nonnull_arg);
          return;
        }
      } else if constexpr (user_deserialize_fn<arg_t> != nullptr) {
        auto *fn_ptr = +user_deserialize_fn<arg_t>;
        using fn_info = detail::get_fn_info<decltype(fn_ptr)>;
        using from_type = typename fn_info::template arg_type<0>;
        std::decay_t<from_type> from_arg;
        self(from_arg, self);
        arg = fn_ptr(std::move(from_arg));
        return;
      } else {
        static_assert(detail::dependent_false<arg_t>);
      }
      idx++;

    };
    (void)column_dispatcher;
    (column_dispatcher(std::forward<Ts>(args), column_dispatcher), ...);
    first_invocation = false;
    return true;
  }

  using PutCallbackType = std::function<void(sqlite3_stmt *)>;

  QueryResult(sqlite3_stmt *stmt_, PutCallbackType put_cb_)
      : stmt(stmt_), put_cb(put_cb_) {
    ret = sqlite3_step(stmt);
  }

  QueryResult(const QueryResult &) = delete;
  QueryResult &operator=(const QueryResult &) = delete;

  sqlite3_stmt *stmt = nullptr;
  PutCallbackType put_cb;
  int ret = -1;
  bool first_invocation = true;

};

// The `PreparedStmtCache` is a cache of available prepared statements for
// reuse corresponding to the query given by `query_str`.
template <const auto &query_str>
class PreparedStmtCache {

 public:
  static inline void put_tls(sqlite3_stmt *stmt, Connection &connection) {
    singleton_tls(connection).internal_put(stmt);
  }

  static inline sqlite3_stmt *get_tls(Connection &connection) {
    return singleton_tls(connection).internal_get();
  }

 private:
  PreparedStmtCache(Connection &connection)
    : _connection(connection),
      first_free_stmt(nullptr), other_free_stmts() { }

  ~PreparedStmtCache(void) {
    sqlite3_finalize(first_free_stmt);
    for (auto stmt : other_free_stmts) {
      sqlite3_finalize(stmt);
    }
  }

  static PreparedStmtCache<query_str> &singleton_tls(Connection &connection) {
    static thread_local PreparedStmtCache<query_str> object(connection);
    return object;
  }

  sqlite3_stmt *internal_get(void) {
    if (first_free_stmt != nullptr) {
      sqlite3_stmt *stmt = nullptr;
      std::swap(first_free_stmt, stmt);
      return stmt;
    } else if (!other_free_stmts.empty()) {
      sqlite3_stmt *stmt = other_free_stmts.back();
      other_free_stmts.pop_back();
      return stmt;
    } else {
      static const auto saved_query_str = detail::maybe_invoke(query_str);
      // If no prepared statement is available for reuse, make a new one.
      sqlite3_stmt *stmt;
      std::string_view query_str_view = saved_query_str;
      auto ret = sqlite3_prepare_v3(_connection.db_handle,
                                    query_str_view.data(),
                                    query_str_view.length() + 1,
                                    SQLITE_PREPARE_PERSISTENT,
                                    &stmt, nullptr);
      if (ret != SQLITE_OK) {
        throw error{ret};
      }
      return stmt;
    }
  }

  // This is called by the row fetcher returned by query<query_str, ...>().
  void internal_put(sqlite3_stmt *stmt) {
    if (first_free_stmt == nullptr) {
      first_free_stmt = stmt;
    } else {
      other_free_stmts.push_back(stmt);
    }
  }

  Connection &_connection;
  sqlite3_stmt *first_free_stmt;
  std::vector<sqlite3_stmt *> other_free_stmts;
};

class Database {
public:

  Database(const std::string &name)
    : _db_name(name), _connection(name) {}

public:
  // Prepare or reuse a statement corresponding to the query string QUERY_STR,
  // binding BIND_ARGS to the parameters ?1, ?2, ..., of the statement.
  // Returns a QueryResult object, with which one can step through the results
  // returned by the query.
  template <const auto &query_str, typename... Ts>
  QueryResult query(Ts &&...bind_args) {
    auto stmt = PreparedStmtCache<query_str>::get_tls(_connection);

    // Via the fold expression right below, `bind_dispatcher` is called on
    // each argument passed in to `query()` and binds the argument to the
    // statement according to the argument's type, using the correct SQL C
    // API function.
    int idx = 1;
    auto bind_dispatcher = [&stmt, &idx] (const auto &arg, auto &self) {

      using arg_t = std::decay_t<decltype(arg)>;
      if constexpr (std::is_integral_v<arg_t>) {
        sqlite3_bind_int64(stmt, idx, arg);
      } else if constexpr (std::is_same_v<const char *, arg_t> ||
                           std::is_same_v<char *, arg_t>) {
        sqlite3_bind_text(stmt, idx, arg, strlen(arg), SQLITE_STATIC);
      } else if constexpr (std::is_same_v<std::string, arg_t>) {
        sqlite3_bind_text(stmt, idx, &arg[0], arg.size(), SQLITE_STATIC);
      } else if constexpr (std::is_same_v<blob, arg_t> ||
                           std::is_same_v<blob_view, arg_t>) {
        sqlite3_bind_blob(stmt, idx, &arg[0], arg.size(), SQLITE_STATIC);
      } else if constexpr (std::is_same_v<std::nullopt_t, arg_t>) {
        sqlite3_bind_null(stmt, idx);
      } else if constexpr (detail::is_std_optional_type<arg_t>) {
        if (arg) {
          self(*arg, self);
          return;
        } else {
          sqlite3_bind_null(stmt, idx);
        }
      } else if constexpr (std::is_null_pointer_v<arg_t>){
        sqlite3_bind_null(stmt, idx);
      } else {
        static_assert(detail::dependent_false<arg_t>);
      }
      idx++;

    };
    (void)bind_dispatcher;
    (bind_dispatcher(std::forward<Ts>(bind_args), bind_dispatcher), ...);

    auto put_tls = [&]( auto s ) {
      return PreparedStmtCache<query_str>::put_tls(s, _connection);
    };
    return QueryResult(stmt, put_tls);
  }

  auto transactionGuard(void);

private:

  Connection _connection;
  std::string _db_name;
};


// A TransactionGuard object starts a SQLite transaction when constructed,
// and when destructed either commits or rolls back the transaction,
// depending on whether the object is being destroyed as a result of stack
// unwinding caused by an uncaught exception.
class TransactionGuard {
public:

  void rollback() {
    if (!transaction_active) {
      throw error{SQLITE_ERROR};
    }
    rollbackTransaction();
    transaction_active = false;
  }

  void commit() {
    if (!transaction_active) {
      throw error{SQLITE_ERROR};
    }
    commitTransaction();
    transaction_active = false;
  }

  TransactionGuard(const TransactionGuard &) = delete;
  TransactionGuard &operator=(const TransactionGuard &) = delete;

private:

  TransactionGuard(Database &db) : _db(db) {
    beginTransaction();
    transaction_active = true;
  }

  ~TransactionGuard() {
    if (!transaction_active)
      return;
    if (std::uncaught_exceptions() == uncaught_exception_count) {
      commit();
    } else {
      rollback();
    }
  }

  // Begin a SQLite transaction.
  void beginTransaction(void) {
    static const char begin_transaction_query[] = "begin transaction";
    _db.query<begin_transaction_query>();
  }

  // Commit the active SQLite transaction.
  void commitTransaction(void) {
    static const char commit_transaction_query[] = "commit transaction";
    _db.query<commit_transaction_query>();
  }

  // Roll back the active SQLite transaction.
  void rollbackTransaction(void) {
    static const char rollback_transaction_query[] = "rollback transaction";
    _db.query<rollback_transaction_query>();
  }

  friend Database;

  Database &_db;
  const int uncaught_exception_count = std::uncaught_exceptions();
  bool transaction_active;
};

inline auto Database::transactionGuard(void) {
    return TransactionGuard(*this);
}

} // namespace sqlite
