// Copyright John Maddock 2006.
// Copyright Paul A. Bristow 2007, 2009
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <boost/math/concepts/real_concept.hpp>
#include <boost/math/special_functions/math_fwd.hpp>
#include <boost/test/test_exec_monitor.hpp>
#include <boost/test/floating_point_comparison.hpp>
#include <boost/math/tools/stats.hpp>
#include <boost/math/tools/test.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/type_traits/is_floating_point.hpp>
#include <boost/array.hpp>
#include "functor.hpp"

#include "handle_test_result.hpp"
#include "test_zeta_hooks.hpp"
#include "table_type.hpp"

#ifndef SC_
#define SC_(x) static_cast<typename table_type<T>::type>(BOOST_JOIN(x, L))
#endif

template <class Real, class T>
void do_test_zeta(const T& data, const char* type_name, const char* test_name)
{
   //
   // test zeta(T) against data:
   //
   using namespace std;
   typedef typename T::value_type row_type;
   typedef Real                   value_type;

   std::cout << test_name << " with type " << type_name << std::endl;

   typedef value_type (*pg)(value_type);
#if defined(BOOST_MATH_NO_DEDUCED_FUNCTION_POINTERS)
   pg funcp = boost::math::zeta<value_type>;
#else
   pg funcp = boost::math::zeta;
#endif

   boost::math::tools::test_result<value_type> result;
   //
   // test zeta against data:
   //
   result = boost::math::tools::test_hetero<Real>(
      data,
      bind_func<Real>(funcp, 0),
      extract_result<Real>(1));
   handle_test_result(result, data[result.worst()], result.worst(), type_name, "boost::math::zeta", test_name);
#ifdef TEST_OTHER
   if(boost::is_floating_point<value_type>::value)
   {
      funcp = other::zeta;

      result = boost::math::tools::test_hetero<Real>(
         data,
         bind_func<Real>(funcp, 0),
         extract_result<Real>(1));
      handle_test_result(result, data[result.worst()], result.worst(), type_name, "other::zeta", test_name);
   }
#endif
   std::cout << std::endl;
}
template <class T>
void test_zeta(T, const char* name)
{
   //
   // The actual test data is rather verbose, so it's in a separate file
   //
#include "zeta_data.ipp"
   do_test_zeta<T>(zeta_data, name, "Zeta: Random values greater than 1");
#include "zeta_neg_data.ipp"
   do_test_zeta<T>(zeta_neg_data, name, "Zeta: Random values less than 1");
#include "zeta_1_up_data.ipp"
   do_test_zeta<T>(zeta_1_up_data, name, "Zeta: Values close to and greater than 1");
#include "zeta_1_below_data.ipp"
   do_test_zeta<T>(zeta_1_below_data, name, "Zeta: Values close to and less than 1");
}

extern "C" double zetac(double);

template <class T>
void test_spots(T, const char* t)
{
   std::cout << "Testing basic sanity checks for type " << t << std::endl;
   //
   // Basic sanity checks, tolerance is either 5 or 10 epsilon 
   // expressed as a percentage:
   //
   T tolerance = boost::math::tools::epsilon<T>() * 100 *
      (boost::is_floating_point<T>::value ? 5 : 10);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(0.125)), static_cast<T>(-0.63277562349869525529352526763564627152686379131122L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(1023) / static_cast<T>(1024)), static_cast<T>(-1023.4228554489429786541032870895167448906103303056L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(1025) / static_cast<T>(1024)), static_cast<T>(1024.5772867695045940578681624248887776501597556226L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(0.5)), static_cast<T>(-1.46035450880958681288949915251529801246722933101258149054289L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(1.125)), static_cast<T>(8.5862412945105752999607544082693023591996301183069L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(2)), static_cast<T>(1.6449340668482264364724151666460251892189499012068L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(3.5)), static_cast<T>(1.1267338673170566464278124918549842722219969574036L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(4)), static_cast<T>(1.08232323371113819151600369654116790277475095191872690768298L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(4 + static_cast<T>(1) / 1024), static_cast<T>(1.08225596856391369799036835439238249195298434901488518878804L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(4.5)), static_cast<T>(1.05470751076145426402296728896028011727249383295625173068468L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(6.5)), static_cast<T>(1.01200589988852479610078491680478352908773213619144808841031L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(7.5)), static_cast<T>(1.00582672753652280770224164440459408011782510096320822989663L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(8.125)), static_cast<T>(1.0037305205308161603183307711439385250181080293472L), 2 * tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(16.125)), static_cast<T>(1.0000140128224754088474783648500235958510030511915L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(0)), static_cast<T>(-0.5L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-0.125)), static_cast<T>(-0.39906966894504503550986928301421235400280637468895L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-1)), static_cast<T>(-0.083333333333333333333333333333333333333333333333333L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-2)), static_cast<T>(0L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-2.5)), static_cast<T>(0.0085169287778503305423585670283444869362759902200745L), tolerance * 3);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-3)), static_cast<T>(0.0083333333333333333333333333333333333333333333333333L), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-4)), static_cast<T>(0), tolerance);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-20)), static_cast<T>(0), tolerance * 100);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-21)), static_cast<T>(-281.46014492753623188405797101449275362318840579710L), tolerance * 100);
   BOOST_CHECK_CLOSE(::boost::math::zeta(static_cast<T>(-30.125)), static_cast<T>(2.2762941726834511267740045451463455513839970804578e7L), tolerance * 100);
}

