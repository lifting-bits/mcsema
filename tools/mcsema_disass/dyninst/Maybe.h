/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

// Replace with std::optional once C++17 is supported
template <typename T>
struct Maybe {
  T val;
  bool contains;

  Maybe(T t) : val(std::move(t)), contains(true) {}

  Maybe(const Maybe<T> &other) : val(other.val), contains(other.contains) {}

  Maybe(Maybe<T> &&other) noexcept(std::is_nothrow_move_constructible<T>::value)
      : val(std::move(other.val)),
        contains(other.contains) {
    other.contains = false;
  }

  Maybe &operator=(Maybe<T> other) {
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

  const T *operator->() const {
    return &val;
  }

  T *operator->() {
    return &val;
  }

  const T &operator*() const {
    return val;
  }

  T &operator*() {
    return val;
  }

  constexpr T &value() {
    return val;
  }

  constexpr const T &value() const {
    return val;
  }
};
