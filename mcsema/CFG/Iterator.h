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

#include <memory>
#include <mcsema/CFG/Util.h>

namespace mcsema::cfg {

namespace details {
  struct Iterator_impl;
} // namespace details

class Module;

template<typename Entry>
struct WeakIterator {

  using data_t = typename Entry::data_t;
  using maybe_data_t = std::optional<data_t>;

  maybe_data_t Fetch();

  ~WeakIterator();

private:
  friend Module;

  using Impl_t = std::unique_ptr<details::Iterator_impl>;
  WeakIterator(Impl_t &&impl);

  Impl_t impl;
};

} // namespace mcsema::cfg
