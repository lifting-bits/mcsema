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

#include <mcsema/CFG/Util.h>

#include <memory>

namespace mcsema::ws {

namespace details {
struct DataIterator_impl;
struct ObjectIterator_impl;
}  // namespace details

class Module;
class BasicBlock;
class Function;

/* Due to some underlying problems it was too complicated to implement proper C++
 * iterators, so unfortunately nice for (X : A) is not viable atm.
 *
 * Iterators can be created only by API objects and only method Fetch is available,
 * which returns empty `std::optional` if there are no more objects to iterate over.
 */

// Fetch returns objects
template <typename Entry>
struct WeakObjectIterator {
  using data_t = Entry;
  using maybe_data_t = std::optional<data_t>;

  maybe_data_t Fetch();

  ~WeakObjectIterator();

 private:
  friend Module;
  friend Function;
  friend BasicBlock;

  using Impl_t = std::unique_ptr<details::ObjectIterator_impl>;
  WeakObjectIterator(Impl_t &&impl);

  Impl_t impl;
};

// Fetch returns Entry::data_t
template <typename Entry>
struct WeakDataIterator {

  using data_t = typename Entry::data_t;
  using maybe_data_t = std::optional<data_t>;

  maybe_data_t Fetch();

  ~WeakDataIterator();

 private:
  friend Module;
  friend BasicBlock;

  using Impl_t = std::unique_ptr<details::DataIterator_impl>;
  WeakDataIterator(Impl_t &&impl);

  Impl_t impl;
};

}  // namespace mcsema::ws
