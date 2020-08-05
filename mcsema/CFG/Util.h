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

#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace mcsema::ws {
namespace util {


// Utility class used during creation of query strings.
// Appends whitespace at the end of each inserted token via `operator<<`. Method `append`
// only inserts token without any formatting.
// TODO(lukas): c++20 constexpr everything with std::string.
template <std::size_t preallocate = 64>
struct QString {
  std::string _data;

  using self_f = QString<preallocate>;

  QString() {
    _data.reserve(preallocate);
  }

  QString(std::string &&str, bool space = true)
      : _data(std::move(str) + (space ? " " : "")) {
    _data.reserve(preallocate);
  }

  std::string take() {
    return std::move(_data);
  }

  self_f operator<<(const std::string &str) {
    _data.append(str).append(" ");
    return *this;
  }

  self_f append(const std::string &str) {
    _data += str;
    return *this;
  }
};

// TODO(lukas): Refactor out
template <typename T>
constexpr bool is_std_optional_t = false;
template <typename T>
constexpr bool is_std_optional_t<std::optional<T>> = true;

template <size_t, typename...>
struct Get_impl {};

template <typename H, typename... Tail>
struct Get_impl<0, H, Tail...> {
  using type = H;
};


template <size_t Idx, typename H, typename... Tail>
struct Get_impl<Idx, H, Tail...> {
  using type = typename Get_impl<Idx - 1, Tail...>::type;
};


template <typename... Args>
struct TypeList {
  constexpr static uint64_t size = sizeof...(Args);

  template <typename... rhs>
  constexpr static auto concat(TypeList<rhs...>) {
    return TypeList<Args..., rhs...>();
  }

  template <size_t idx>
  using Get = typename Get_impl<idx, Args...>::type;
};

template <typename T, typename = int>
struct HasPublicAPI : std::false_type {};

template <typename T>
struct HasPublicAPI<T, decltype((void) T::is_public_api, 0)> : std::true_type {
};

template <typename T>
struct HasPublicAPI<std::optional<T>> : HasPublicAPI<T> {};

template <typename Arg>
struct StripAPI_ {
  using type = std::conditional_t<HasPublicAPI<Arg>::value, int64_t, Arg>;
};

template <typename Arg>
struct StripAPI_<std::optional<Arg>> {
  using type = std::conditional_t<HasPublicAPI<Arg>::value,
                                  std::optional<int64_t>, std::optional<Arg>>;
};

template <class... Args>
struct StripAPI {
  using type = TypeList<typename StripAPI_<Args>::type...>;
};

namespace details {

template <typename T>
struct FirstArg {};

// Stores first argument of F in type
template <typename F, typename Ret, typename Arg>
struct FirstArg<Ret (F::*)(Arg)> {
  using type = Arg;
};

template <typename F, typename Ret, typename Arg>
struct FirstArg<Ret (F::*)(Arg) const> {
  using type = Arg;
};

}  // namespace details

// Implements "switch" on ea, which is for example useful if there is a `target_ea`
// but there is no way to tell which object it corresponds to (if any at all)
// Match allows partial solution to this problem:
// Match(module, _, 0x400400, [&](BasicBlock) { ... },
//                            [&](Function) { ... } );
// If nothing was matched, `False` is returned
template <typename HasCtx>
bool Match(HasCtx &has_ctx, int64_t module_id, uint64_t ea) {
  return false;
}

template <typename HasCtx, typename Target, typename... Targets>
bool Match(HasCtx &has_ctx, int64_t module_id, uint64_t ea, Target target,
           Targets &&... targets) {

  using Self = typename details::FirstArg<decltype(&Target::operator())>::type;

  if (auto obj = Self::MatchEa(has_ctx, module_id, ea)) {
    target(std::move(*obj));
    return true;
  }
  return Match(has_ctx, module_id, ea, std::forward<Targets>(targets)...);
}

// Makes iteration over objects using WeakPointers shorter
template <typename WeakIt, typename F>
void ForEach(WeakIt it, F f) {
  while (auto data = it.Fetch()) {
    f(*data);
  }
}

template <typename... Fields, typename Result>
auto GetFromList(Result &r, TypeList<Fields...>) {
  return *r.template Get<Fields...>();
}

template <typename To, size_t... Indices, typename From>
To to_struct_(std::index_sequence<Indices...>, From &&from) {
  return {std::get<Indices>(std::forward<From>(from))...};
}


template <typename To, typename From>
To to_struct(From &&from) {
  using From_t = std::decay_t<From>;
  return to_struct_<To>(std::make_index_sequence<std::tuple_size_v<From_t>>(),
                        std::forward<From>(from));
}

template <typename To, typename From>
std::optional<To> maybe_to_struct(std::optional<From> &&from) {
  if (!from)
    return {};
  return {to_struct<To>(*from)};
}

template <typename R, typename Yield, typename... Args>
void iterate(R &&r, Yield yield, Args &&... args) {
  while (r(std::forward<Args>(args)...)) {
    yield(std::forward<Args>(args)...);
  }
}

}  // namespace util
}  // namespace mcsema::ws
