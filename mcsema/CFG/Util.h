#pragma once

#include <utility>

namespace mcsema::cfg {
namespace util
{

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
