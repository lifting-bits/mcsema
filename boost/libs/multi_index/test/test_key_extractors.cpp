/* Boost.MultiIndex test for key extractors.
 *
 * Copyright 2003-2009 Joaquin M Lopez Munoz.
 * Distributed under the Boost Software License, Version 1.0.
 * (See accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 *
 * See http://www.boost.org/libs/multi_index for library home page.
 */

#include "test_key_extractors.hpp"

#include <boost/config.hpp> /* keep it first to prevent nasty warns in MSVC */
#include "pre_multi_index.hpp"
#include <boost/multi_index/key_extractors.hpp>
#include <boost/ref.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/test/test_tools.hpp>
#include <list>
#include <memory>

using namespace boost::multi_index;
using namespace boost::tuples;

struct test_class
{
  int       int_member;
  const int int_cmember;

  bool bool_mem_fun_const()const{return true;}
  bool bool_mem_fun(){return false;}

  static bool bool_global_fun(test_class){return true;}
  static bool bool_global_fun_const_ref(const test_class&){return false;}
  static bool bool_global_fun_ref(test_class&){return true;}

  test_class(int i=0):int_member(i),int_cmember(i){}
  test_class(int i,int j):int_member(i),int_cmember(j){}

  test_class& operator=(const test_class& x)
  {
    int_member=x.int_member;
    return *this;
  }

  bool operator<(const test_class& x)const
  {
    if(int_member<x.int_member)return true;
    if(x.int_member<int_member)return false;
    return int_cmember<x.int_cmember;
  }

  bool operator==(const test_class& x)const
  {
    return int_member==x.int_member&&int_cmember==x.int_cmember;
  }
};

struct test_derived_class:test_class
{
  test_derived_class(int i=0):test_class(i){}
  test_derived_class(int i,int j):test_class(i,j){}
};

BOOST_BROKEN_COMPILER_TYPE_TRAITS_SPECIALIZATION(test_class)
BOOST_BROKEN_COMPILER_TYPE_TRAITS_SPECIALIZATION(test_derived_class)

typedef identity<test_class>                                       idn;
typedef identity<const test_class>                                 cidn;
typedef BOOST_MULTI_INDEX_MEMBER(test_class,int,int_member)        key_m;
typedef BOOST_MULTI_INDEX_MEMBER(test_class,const int,int_member)  ckey_m;
typedef BOOST_MULTI_INDEX_MEMBER(test_class,const int,int_cmember) key_cm;
typedef BOOST_MULTI_INDEX_CONST_MEM_FUN(
          test_class,bool,bool_mem_fun_const)                      key_cmf;
typedef BOOST_MULTI_INDEX_MEM_FUN(test_class,bool,bool_mem_fun)    key_mf;
typedef global_fun<test_class,bool,&test_class::bool_global_fun>   key_gf;
typedef global_fun<
          const test_class&,bool,
          &test_class::bool_global_fun_const_ref
        >                                                          key_gcrf;
typedef global_fun<
          test_class&,bool,
          &test_class::bool_global_fun_ref
        >                                                          key_grf;
typedef composite_key<
          test_class,
          idn,
          key_m,
          key_cm,
          key_cmf
        >                                                          compkey;
typedef composite_key<
          test_class,
          cidn,
          ckey_m
        >                                                          ccompkey;
typedef composite_key<
          boost::reference_wrapper<test_class>,
          key_mf
        >                                                          ccompw_key;

#if !defined(BOOST_NO_SFINAE)
/* testcases for problems with non-copyable classes reported at
 * http://lists.boost.org/Archives/boost/2006/04/103065.php
 */

struct test_nc_class
{
  int       int_member;
  const int int_cmember;

  bool bool_mem_fun_const()const{return true;}
  bool bool_mem_fun(){return false;}

  static bool bool_global_fun_const_ref(const test_nc_class&){return false;}
  static bool bool_global_fun_ref(test_nc_class&){return true;}

  test_nc_class(int i=0):int_member(i),int_cmember(i){}
  test_nc_class(int i,int j):int_member(i),int_cmember(j){}

  bool operator==(const test_nc_class& x)const
  {
    return int_member==x.int_member&&int_cmember==x.int_cmember;
  }

private:
  test_nc_class(const test_nc_class&);
  test_nc_class& operator=(const test_nc_class&);
};

struct test_nc_derived_class:test_nc_class
{
  test_nc_derived_class(int i=0):test_nc_class(i){}
  test_nc_derived_class(int i,int j):test_nc_class(i,j){}
};

BOOST_BROKEN_COMPILER_TYPE_TRAITS_SPECIALIZATION(test_nc_class)
BOOST_BROKEN_COMPILER_TYPE_TRAITS_SPECIALIZATION(test_nc_derived_class)

typedef identity<test_nc_class>                                nc_idn;
typedef identity<const test_nc_class>                          nc_cidn;
typedef BOOST_MULTI_INDEX_MEMBER(test_nc_class,int,int_member) nc_key_m;
typedef BOOST_MULTI_INDEX_MEMBER(
          test_nc_class,const int,int_member)                  nc_ckey_m;
typedef BOOST_MULTI_INDEX_CONST_MEM_FUN(
          test_nc_class,bool,bool_mem_fun_const)               nc_key_cmf;
typedef BOOST_MULTI_INDEX_MEM_FUN(
          test_nc_class,bool,bool_mem_fun)                     nc_key_mf;
typedef global_fun<
          const test_nc_class&,bool,
          &test_nc_class::bool_global_fun_const_ref
        >                                                      nc_key_gcrf;
typedef global_fun<
          test_nc_class&,bool,
          &test_nc_class::bool_global_fun_ref
        >                                                      nc_key_grf;
typedef composite_key<
          test_nc_class,
          nc_idn,
          nc_key_m,
          nc_ckey_m,
          nc_key_cmf
        >                                                      nc_compkey;
#endif

void test_key_extractors()
{
  idn        id;
  cidn       cid;
  key_m      k_m;
  ckey_m     ck_m;
  key_cm     k_cm;
  key_cmf    k_cmf;
  key_mf     k_mf;
  key_gf     k_gf;
  key_gcrf   k_gcrf;
  key_grf    k_grf;
  compkey    cmpk;
  ccompkey   ccmpk;
  ccompw_key ccmpk_w;

  test_derived_class                         td(-1,0);
  const test_derived_class&                  ctdr=td;

  test_class&                                tr=td;
  const test_class&                          ctr=tr;

  test_derived_class*                        tdp=&td;
  const test_derived_class*                  ctdp=&ctdr;

  test_class*                                tp=&tr;
  const test_class*                          ctp=&tr;

  test_class**                               tpp=&tp;
  const test_class**                         ctpp=&ctp;

  std::auto_ptr<test_class*>                 tap(new test_class*(tp));
  std::auto_ptr<const test_class*>           ctap(new const test_class*(ctp));

  boost::reference_wrapper<test_class>       tw(tr);
  boost::reference_wrapper<const test_class> ctw(tr);

  id(tr).int_member=0;
  BOOST_CHECK(id(tr).int_member==0);
  BOOST_CHECK(cid(tr).int_member==0);
  BOOST_CHECK(k_m(tr)==0);
  BOOST_CHECK(ck_m(tr)==0);
  BOOST_CHECK(cmpk(tr)==make_tuple(test_class(0,0),0,0,true));
  BOOST_CHECK(ccmpk(tr)==make_tuple(test_class(0,0),0));
  BOOST_CHECK(id(ctr).int_member==0);
  BOOST_CHECK(cid(ctr).int_member==0);
  BOOST_CHECK(k_m(ctr)==0);
  BOOST_CHECK(ck_m(ctr)==0);
  BOOST_CHECK(cmpk(ctr)==make_tuple(test_class(0,0),0,0,true));
  BOOST_CHECK(ccmpk(ctr)==make_tuple(test_class(0,0),0));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(id(td).int_member==0);
  BOOST_CHECK(cid(td).int_member==0);
  BOOST_CHECK(k_m(td)==0);
  BOOST_CHECK(ck_m(td)==0);
  BOOST_CHECK(cmpk(td)==make_tuple(test_class(0,0),0,0,true));
  BOOST_CHECK(ccmpk(td)==make_tuple(test_class(0,0),0));
  BOOST_CHECK(id(ctdr).int_member==0);
  BOOST_CHECK(cid(ctdr).int_member==0);
  BOOST_CHECK(k_m(ctdr)==0);
  BOOST_CHECK(ck_m(ctdr)==0);
  BOOST_CHECK(cmpk(ctdr)==make_tuple(test_class(0,0),0,0,true));
  BOOST_CHECK(ccmpk(ctdr)==make_tuple(test_class(0,0),0));
#endif

  k_m(tr)=1;
  BOOST_CHECK(id(tp).int_member==1);
  BOOST_CHECK(cid(tp).int_member==1);
  BOOST_CHECK(k_m(tp)==1);
  BOOST_CHECK(ck_m(tp)==1);
  BOOST_CHECK(cmpk(tp)==make_tuple(test_class(1,0),1,0,true));
  BOOST_CHECK(ccmpk(tp)==make_tuple(test_class(1,0),1));
  BOOST_CHECK(cid(ctp).int_member==1);
  BOOST_CHECK(ck_m(ctp)==1);
  BOOST_CHECK(cmpk(ctp)==make_tuple(test_class(1,0),1,0,true));
  BOOST_CHECK(ccmpk(ctp)==make_tuple(test_class(1,0),1));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(id(tdp).int_member==1);
  BOOST_CHECK(cid(tdp).int_member==1);
  BOOST_CHECK(k_m(tdp)==1);
  BOOST_CHECK(ck_m(tdp)==1);
  BOOST_CHECK(cmpk(tdp)==make_tuple(test_class(1,0),1,0,true));
  BOOST_CHECK(ccmpk(tdp)==make_tuple(test_class(1,0),1));
  BOOST_CHECK(cid(ctdp).int_member==1);
  BOOST_CHECK(ck_m(ctdp)==1);
  BOOST_CHECK(cmpk(ctdp)==make_tuple(test_class(1,0),1,0,true));
  BOOST_CHECK(ccmpk(ctdp)==make_tuple(test_class(1,0),1));
#endif

  k_m(tp)=2;
  BOOST_CHECK(id(tpp).int_member==2);
  BOOST_CHECK(cid(tpp).int_member==2);
  BOOST_CHECK(k_m(tpp)==2);
  BOOST_CHECK(ck_m(tpp)==2);
  BOOST_CHECK(cmpk(tpp)==make_tuple(test_class(2,0),2,0,true));
  BOOST_CHECK(ccmpk(tpp)==make_tuple(test_class(2,0),2));
  BOOST_CHECK(cid(ctpp).int_member==2);
  BOOST_CHECK(ck_m(ctpp)==2);
  BOOST_CHECK(cmpk(ctpp)==make_tuple(test_class(2,0),2,0,true));
  BOOST_CHECK(ccmpk(ctpp)==make_tuple(test_class(2,0),2));

  k_m(tpp)=3;
  BOOST_CHECK(id(tap).int_member==3);
  BOOST_CHECK(cid(tap).int_member==3);
  BOOST_CHECK(k_m(tap)==3);
  BOOST_CHECK(ck_m(tap)==3);
  BOOST_CHECK(cmpk(tap)==make_tuple(test_class(3,0),3,0,true));
  BOOST_CHECK(ccmpk(tap)==make_tuple(test_class(3,0),3));
  BOOST_CHECK(cid(ctap).int_member==3);
  BOOST_CHECK(ck_m(ctap)==3);
  BOOST_CHECK(cmpk(ctap)==make_tuple(test_class(3,0),3,0,true));
  BOOST_CHECK(ccmpk(ctap)==make_tuple(test_class(3,0),3));

  k_m(tap)=4;
  BOOST_CHECK(id(tw).int_member==4);
  BOOST_CHECK(cid(tw).int_member==4);
  BOOST_CHECK(k_m(tw)==4);
  BOOST_CHECK(ck_m(tw)==4);
  BOOST_CHECK(cmpk(tw)==make_tuple(test_class(4,0),4,0,true));
  BOOST_CHECK(ccmpk(tw)==make_tuple(test_class(4,0),4));

  k_m(tw)=5;
  BOOST_CHECK(id(ctw).int_member==5);
  BOOST_CHECK(cid(ctw).int_member==5);
  BOOST_CHECK(k_m(ctw)==5);
  BOOST_CHECK(ck_m(ctw)==5);
  BOOST_CHECK(cmpk(ctw)==make_tuple(test_class(5,0),5,0,true));
  BOOST_CHECK(ccmpk(ctw)==make_tuple(test_class(5,0),5));

  BOOST_CHECK(k_cm(tr)==0);
  BOOST_CHECK(k_cm(ctr)==0);

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_cm(td)==0);
  BOOST_CHECK(k_cm(ctdr)==0);
#endif

  BOOST_CHECK(k_cm(tp)==0);
  BOOST_CHECK(k_cm(ctp)==0);

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_cm(tdp)==0);
  BOOST_CHECK(k_cm(ctdp)==0);
#endif
  
  BOOST_CHECK(k_cm(tpp)==0);
  BOOST_CHECK(k_cm(ctpp)==0);
  BOOST_CHECK(k_cm(tap)==0);
  BOOST_CHECK(k_cm(ctap)==0);

  BOOST_CHECK(k_cm(tw)==0);
  BOOST_CHECK(k_cm(ctw)==0);

  BOOST_CHECK(k_cmf(tr));
  BOOST_CHECK(k_cmf(ctr));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_cmf(td));
  BOOST_CHECK(k_cmf(ctdr));
#endif

  BOOST_CHECK(k_cmf(tp));
  BOOST_CHECK(k_cmf(ctp));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_cmf(tdp));
  BOOST_CHECK(k_cmf(ctdp));
#endif

  BOOST_CHECK(k_cmf(tpp));
  BOOST_CHECK(k_cmf(ctpp));
  BOOST_CHECK(k_cmf(tap));
  BOOST_CHECK(k_cmf(ctap));

  BOOST_CHECK(k_cmf(tw));
  BOOST_CHECK(k_cmf(ctw));

  BOOST_CHECK(!k_mf(tr));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(!k_mf(td));
#endif

  BOOST_CHECK(!k_mf(tp));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(!k_mf(tdp));
#endif

  BOOST_CHECK(!k_mf(tpp));
  BOOST_CHECK(!k_mf(tap));
  BOOST_CHECK(!k_mf(tw));

  BOOST_CHECK(k_gf(tr));
  BOOST_CHECK(k_gf(ctr));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_gf(td));
  BOOST_CHECK(k_gf(ctdr));
#endif

  BOOST_CHECK(k_gf(tp));
  BOOST_CHECK(k_gf(ctp));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_gf(tdp));
  BOOST_CHECK(k_gf(ctdp));
#endif

  BOOST_CHECK(k_gf(tpp));
  BOOST_CHECK(k_gf(ctpp));
  BOOST_CHECK(k_gf(tap));
  BOOST_CHECK(k_gf(ctap));

  BOOST_CHECK(k_gf(tw));
  BOOST_CHECK(k_gf(ctw));
  
  BOOST_CHECK(!k_gcrf(tr));
  BOOST_CHECK(!k_gcrf(ctr));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(!k_gcrf(td));
  BOOST_CHECK(!k_gcrf(ctdr));
#endif

  BOOST_CHECK(!k_gcrf(tp));
  BOOST_CHECK(!k_gcrf(ctp));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(!k_gcrf(tdp));
  BOOST_CHECK(!k_gcrf(ctdp));
#endif

  BOOST_CHECK(!k_gcrf(tpp));
  BOOST_CHECK(!k_gcrf(ctpp));
  BOOST_CHECK(!k_gcrf(tap));
  BOOST_CHECK(!k_gcrf(ctap));

  BOOST_CHECK(!k_gcrf(tw));
  BOOST_CHECK(!k_gcrf(ctw));

  BOOST_CHECK(k_grf(tr));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_grf(td));
#endif

  BOOST_CHECK(k_grf(tp));

#if !defined(BOOST_NO_SFINAE)
  BOOST_CHECK(k_grf(tdp));
#endif

  BOOST_CHECK(k_grf(tpp));
  BOOST_CHECK(k_grf(tap));
  BOOST_CHECK(k_grf(tw));

  BOOST_CHECK(ccmpk_w(tw)==make_tuple(false));

#if !defined(BOOST_NO_SFINAE)
/* testcases for problems with non-copyable classes reported at
 * http://lists.boost.org/Archives/boost/2006/04/103065.php
 */

  nc_idn        nc_id;
  nc_cidn       nc_cid;
  nc_key_m      nc_k_m;
  nc_ckey_m     nc_ck_m;
  nc_key_cmf    nc_k_cmf;
  nc_key_mf     nc_k_mf;
  nc_key_gcrf   nc_k_gcrf;
  nc_key_grf    nc_k_grf;
  nc_compkey    nc_cmpk;

  test_nc_derived_class nc_td(-1,0);

  nc_id(nc_td).int_member=0;
  BOOST_CHECK(nc_id(nc_td).int_member==0);
  BOOST_CHECK(nc_cid(nc_td).int_member==0);

  nc_k_m(&nc_td)=1;
  BOOST_CHECK(nc_k_m(&nc_td)==1);
  BOOST_CHECK(nc_ck_m(&nc_td)==1);

  BOOST_CHECK(nc_k_cmf(nc_td));
  BOOST_CHECK(!nc_k_mf(nc_td));

  BOOST_CHECK(!nc_k_gcrf(nc_td));
  BOOST_CHECK(nc_k_grf(nc_td));

  test_nc_class nc_t(1,0);
  BOOST_CHECK(nc_cmpk(nc_td)==make_tuple(boost::cref(nc_t),1,1,true));
#endif
  
  std::list<test_class> tl;
  for(int i=0;i<20;++i)tl.push_back(test_class(i));

  int j=0;
  for(std::list<test_class>::iterator it=tl.begin();it!=tl.end();++it){
    BOOST_CHECK(k_m(it)==j);
    BOOST_CHECK(k_cm(it)==j);
    BOOST_CHECK(k_cmf(it));
    BOOST_CHECK(!k_mf(it));
    BOOST_CHECK(k_gf(it));
    BOOST_CHECK(!k_gcrf(it));
    BOOST_CHECK(k_grf(it));
    BOOST_CHECK(cmpk(it)==make_tuple(test_class(j),j,j,true));
    BOOST_CHECK(ccmpk(it)==make_tuple(test_class(j),j));
    ++j;
  }
}
