/////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga  2007-2012
//
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/intrusive for documentation.
//
/////////////////////////////////////////////////////////////////////////////
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/slist.hpp>
#include <boost/intrusive/set.hpp>
#include <boost/intrusive/unordered_set.hpp>
#include <boost/intrusive/splay_set.hpp>
#include <boost/intrusive/avl_set.hpp>
#include <boost/intrusive/sg_set.hpp>
#include <boost/intrusive/pointer_traits.hpp>
#include "smart_ptr.hpp"
#include <vector>

using namespace boost::intrusive;

class MyClass

:  public list_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
,  public slist_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
,  public set_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
,  public unordered_set_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
,  public avl_set_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
,  public splay_set_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
,  public bs_set_base_hook
   < void_pointer<smart_ptr<void> >, link_mode<normal_link> >
{
   int int_;

   public:
   MyClass(int i)
      :  int_(i)
   {}

   friend bool operator<(const MyClass &l, const MyClass &r)
   {  return l.int_ < r.int_; }

   friend bool operator==(const MyClass &l, const MyClass &r)
   {  return l.int_ == r.int_; }

   friend std::size_t hash_value(const MyClass &v)
   {  return boost::hash_value(v.int_); }
};

//Define a list that will store MyClass using the public base hook
typedef list<MyClass>            List;
typedef slist<MyClass>           Slist;
typedef set<MyClass>             Set;
typedef unordered_set<MyClass>   USet;
typedef avl_set<MyClass>         AvlSet;
typedef splay_set<MyClass>       SplaySet;
typedef sg_set<MyClass>          SgSet;

int main()
{
   typedef std::vector<MyClass>::iterator VectIt;
   typedef std::vector<MyClass>::reverse_iterator VectRit;

   //Create several MyClass objects, each one with a different value
   std::vector<MyClass> values;
   for(int i = 0; i < 100; ++i)  values.push_back(MyClass(i));

   USet::bucket_type buckets[100];

   List  my_list;
   Slist my_slist;
   Set   my_set;
   USet  my_uset(USet::bucket_traits(pointer_traits<USet::bucket_ptr>::pointer_to(*buckets), 100));

   AvlSet   my_avlset;
   SplaySet my_splayset;
   SgSet    my_sgset;

   //Now insert them in the reverse order
   //in the base hook intrusive list
   for(VectIt it(values.begin()), itend(values.end()); it != itend; ++it){
      my_list.push_front(*it);
      my_slist.push_front(*it);
      my_set.insert(*it);
      my_uset.insert(*it);
      my_avlset.insert(*it);
      my_splayset.insert(*it);
      my_sgset.insert(*it);
   }

   //Now test lists
   {
      List::const_iterator  list_it(my_list.cbegin());
      Slist::const_iterator slist_it(my_slist.cbegin());
      Set::const_reverse_iterator set_rit(my_set.crbegin());
      AvlSet::const_reverse_iterator avl_set_rit(my_avlset.crbegin());
      SplaySet::const_reverse_iterator splay_set_rit(my_splayset.crbegin());
      SgSet::const_reverse_iterator sg_set_rit(my_sgset.crbegin());

      VectRit vect_it(values.rbegin()), vect_itend(values.rend());

      //Test the objects inserted in the base hook list
      for(; vect_it != vect_itend
          ; ++vect_it, ++list_it
          , ++slist_it, ++set_rit
          , ++avl_set_rit, ++splay_set_rit
          , ++sg_set_rit){
         if(&*list_it  != &*vect_it)      return 1;
         if(&*slist_it != &*vect_it)      return 1;
         if(&*set_rit  != &*vect_it)      return 1;
         if(&*avl_set_rit  != &*vect_it)  return 1;
         if(&*splay_set_rit  != &*vect_it)return 1;
         if(&*sg_set_rit  != &*vect_it)   return 1;
         if(my_uset.find(*set_rit) == my_uset.cend())  return 1;
      }
   }

   return 0;
}
