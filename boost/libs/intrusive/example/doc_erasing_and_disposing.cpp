/////////////////////////////////////////////////////////////////////////////
//
// (C) Copyright Ion Gaztanaga  2006-2012
//
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)
//
// See http://www.boost.org/libs/intrusive for documentation.
//
/////////////////////////////////////////////////////////////////////////////
//[doc_erasing_and_disposing
#include <boost/intrusive/list.hpp>

using namespace boost::intrusive;

//A class that can be inserted in an intrusive list
class my_class : public list_base_hook<>
{
   public:
   my_class(int i)
      :  int_(i)
   {}

   int int_;
   //...
};

//Definition of the intrusive list
typedef list<my_class> my_class_list;

//The predicate function
struct is_even
{
   bool operator()(const my_class &c) const
   {  return 0 == (c.int_ % 2);  }
};

//The disposer object function
struct delete_disposer
{
   void operator()(my_class *delete_this)
   {  delete delete_this;  }
};

int main()
{
   const int MaxElem = 100;

   //Fill all the nodes and insert them in the list
   my_class_list list;

   try{
      //Insert new objects in the container
      for(int i = 0; i < MaxElem; ++i) list.push_back(*new my_class(i));

      //Now use remove_and_dispose_if to erase and delete the objects
      list.remove_and_dispose_if(is_even(), delete_disposer());
   }
   catch(...){
      //If something throws, make sure that all the memory is freed
      list.clear_and_dispose(delete_disposer());
      throw;
   }

   //Dispose remaining elements
   list.erase_and_dispose(list.begin(), list.end(), delete_disposer());
   return 0;
}
//]
