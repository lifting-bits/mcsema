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

namespace mcsema::cfg {
namespace util
{

template<typename ...Args>
struct TypeList {};

namespace details {

template<typename T>
struct FirstArg {};

// Stores first argument of F in type
template<typename F, typename Ret, typename Arg>
struct FirstArg<Ret (F::*)(Arg)> {
  using type = Arg;
};

template<typename F, typename Ret, typename Arg>
struct FirstArg<Ret (F::*)(Arg) const> {
  using type = Arg;
};

} // namespace details

// Implements "switch" on ea, which is for example useful if there is a `target_ea`
// but there is no way to tell which object it corresponds to (if any at all)
// Match allows partial solution to this problem:
// Match(module, _, 0x400400, [&](BasicBlock) { ... },
//                            [&](Function) { ... } );
// If nothing was matched, `False` is returned
template<typename HasCtx>
bool Match(HasCtx &has_ctx, int64_t module_id, uint64_t ea) { return false; }

template<typename HasCtx, typename Target, typename ... Targets>
bool Match(
    HasCtx &has_ctx, int64_t module_id, uint64_t ea,
    Target target, Targets &&...targets) {

  using Self = typename details::FirstArg<
      decltype(&Target::operator())
    >::type;

  if (auto obj = Self::MatchEa(has_ctx, module_id, ea)) {
    target(std::move(*obj));
    return true;
  }
  return Match(has_ctx, module_id, ea, std::forward<Targets>(targets)...);
}

// Makes iteration over objects using WeakPointers shorter
template<typename WeakIt, typename F>
void ForEach(WeakIt it, F f) {
  while (auto data = it.Fetch()) {
    f(*data);
  }
}

template<typename To, size_t ...Indices, typename From>
To to_struct_(std::index_sequence<Indices ...>, From &&from) {
  return { std::get<Indices>(std::forward<From>(from))... };
}


template<typename To, typename From>
To to_struct(From &&from) {
  using From_t = std::decay_t<From>;
  return to_struct_<To>(
      std::make_index_sequence<std::tuple_size_v<From_t>>(),
      std::forward<From>(from));
}

template<typename To, typename From>
std::optional<To> maybe_to_struct(std::optional<From> &&from) {
  if (!from)
    return {};
  return { to_struct<To>(*from) };
}

template< typename R, typename Yield, typename ...Args >
void iterate( R &&r, Yield yield, Args &&...args )
{
  while( r( std::forward< Args >( args ) ...  ) )
  {
    yield( std::forward< Args >( args ) ...  );
  }
}

} // namespace util
} // namespace mcsema::cfg
