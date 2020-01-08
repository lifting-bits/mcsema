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

// Replace with std::optional once C++17 is supported
template<typename T>
struct Maybe {
  T val;
  bool contains;

  Maybe(T t) : val(std::move(t)), contains(true) {}

  Maybe(const Maybe<T> &other) : val(other.val), contains(other.contains) {}

  Maybe(Maybe<T> &&other) noexcept(std::is_nothrow_move_constructible<T>::value)
    : val(std::move(other.val)), contains(other.contains) {
    other.contains = false;
  }

  Maybe& operator=(Maybe<T> other) {
    using std::swap;
    swap(val, other.val);
    swap(contains, other.contains);
    return *this;
  }

  Maybe() : contains(false) {}

  ~Maybe() = default;

  constexpr explicit operator bool() const noexcept {
    return contains;
  }

  constexpr bool has_value() const noexcept {
    return contains;
  }

  const T* operator->() const {
    return &val;
  }

  T* operator->() {
    return &val;
  }

  const T& operator*() const {
    return val;
  }

  T& operator*() {
    return val;
  }

  constexpr T& value() {
    return val;
  }

  constexpr const T& value() const {
    return val;
  }
};
