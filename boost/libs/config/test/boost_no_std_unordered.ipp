//  (C) Copyright John Maddock and Dave Abrahams 2002. 
//  Use, modification and distribution are subject to the 
//  Boost Software License, Version 1.0. (See accompanying file 
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

//  See http://www.boost.org/libs/config for most recent version.

//  MACRO:         BOOST_NO_STD_UNORDERED
//  TITLE:         <unordered_map> and <unordered_set>
//  DESCRIPTION:   Check for C++0x unordered container support

#include <unordered_map>
#include <unordered_set>

namespace boost_no_std_unordered{

int test()
{
   std::unordered_map<int, int> im;
   std::unordered_set<int> is;
   std::unordered_multimap<int, int> imm;
   std::unordered_multiset<int> ims;
   return im.size() + is.size() + imm.size() + ims.size(); // all zero
}

}

