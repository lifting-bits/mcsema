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
