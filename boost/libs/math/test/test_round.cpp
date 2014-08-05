//  (C) Copyright John Maddock 2007.
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <pch.hpp>

#include <boost/math/concepts/real_concept.hpp>
#include <boost/test/test_exec_monitor.hpp>
#include <boost/test/floating_point_comparison.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/math/special_functions/trunc.hpp>
#include <boost/math/special_functions/modf.hpp>
#include <boost/math/special_functions/sign.hpp>
#include <boost/random/mersenne_twister.hpp>

boost::mt19937 rng;

template <class T>
T get_random()
{
   //
   // Fill all the bits in T with random values,
   // likewise set the exponent to a random value
   // that will still fit inside a T, and always
   // have a remainder as well as an integer part.
   //
   int bits = boost::math::tools::digits<T>();
   int shift = 0;
   int exponent = rng() % (bits - 4);
   T result = 0;
   while(bits > 0)
   {
      result += ldexp(static_cast<T>(rng()), shift);
      shift += std::numeric_limits<int>::digits;
      bits -= std::numeric_limits<int>::digits;
   }
   return rng() & 1u ? -ldexp(frexp(result, &bits), exponent) : ldexp(frexp(result, &bits), exponent);
}

template <class T, class U>
void check_within_half(T a, U u)
{
   BOOST_MATH_STD_USING
   if(fabs(a-u) > 0.5f)
   {
      BOOST_ERROR("Rounded result differed by more than 0.5 from the original");
      std::cerr << "Values were: " << std::setprecision(35) << std::setw(40)
         << std::left << a << u << std::endl;
   }
   if((fabs(a - u) == 0.5f) && (fabs(static_cast<T>(u)) < fabs(a)))
   {
      BOOST_ERROR("Rounded result was towards zero with boost::round");
      std::cerr << "Values were: " << std::setprecision(35) << std::setw(40)
         << std::left << a << u << std::endl;
   }
}

//
// We may not have an abs overload for long long so provide a fall back:
//
template <class T>
inline T safe_abs(T const& v ...)
{
   return v < 0 ? -v : v;
}

template <class T, class U>
void check_trunc_result(T a, U u)
{
   BOOST_MATH_STD_USING
   if(fabs(a-u) >= 1)
   {
      BOOST_ERROR("Rounded result differed by more than 1 from the original");
      std::cerr << "Values were: " << std::setprecision(35) << std::setw(40)
         << std::left << a << u << std::endl;
   }
   if(abs(a) < safe_abs(u))
   {
      BOOST_ERROR("Truncated result had larger absolute value than the original");
      std::cerr << "Values were: " << std::setprecision(35) << std::setw(40)
         << std::left << a << u << std::endl;
   }
   if(fabs(static_cast<T>(u)) > fabs(a))
   {
      BOOST_ERROR("Rounded result was away from zero with boost::trunc");
      std::cerr << "Values were: " << std::setprecision(35) << std::setw(40)
         << std::left << a << u << std::endl;
   }
}

template <class T, class U>
void check_modf_result(T a, T fract, U ipart)
{
   BOOST_MATH_STD_USING
   if(fract + ipart != a)
   {
      BOOST_ERROR("Fractional and integer results do not add up to the original value");
      std::cerr << "Values were: " << std::setprecision(35) << " "
         << std::left << a << ipart << " " << fract << std::endl;
   }
   if((boost::math::sign(a) != boost::math::sign(fract)) && boost::math::sign(fract))
   {
      BOOST_ERROR("Original and fractional parts have differing signs");
      std::cerr << "Values were: " << std::setprecision(35) << " "
         << std::left << a << ipart << " " << fract << std::endl;
   }
   if((boost::math::sign(a) != boost::math::sign(ipart)) && boost::math::sign(ipart))
   {
      BOOST_ERROR("Original and integer parts have differing signs");
      std::cerr << "Values were: " << std::setprecision(35) << " "
         << std::left << a << ipart << " " << ipart << std::endl;
   }
   if(fabs(a-ipart) >= 1)
   {
      BOOST_ERROR("Rounded result differed by more than 1 from the original");
      std::cerr << "Values were: " << std::setprecision(35) << std::setw(40)
         << std::left << a << ipart << std::endl;
   }
}

template <class T>
void test_round(T, const char* name )
{
   BOOST_MATH_STD_USING

   std::cout << "Testing rounding with type " << name << std::endl;

   for(int i = 0; i < 1000; ++i)
   {
      T arg = get_random<T>();
      T r = boost::math::round(arg);
      check_within_half(arg, r);
      r = boost::math::trunc(arg);
      check_trunc_result(arg, r);
      T frac = boost::math::modf(arg, &r);
      check_modf_result(arg, frac, r);

      if(abs(r) < (std::numeric_limits<int>::max)())
      {
         int i = boost::math::iround(arg);
         check_within_half(arg, i);
         i = boost::math::itrunc(arg);
         check_trunc_result(arg, i);
         r = boost::math::modf(arg, &i);
         check_modf_result(arg, r, i);
      }
      if(std::numeric_limits<T>::digits >= std::numeric_limits<int>::digits)
      {
         int si = boost::math::iround(static_cast<T>((std::numeric_limits<int>::max)()));
         check_within_half(static_cast<T>((std::numeric_limits<int>::max)()), si);
         si = boost::math::iround(static_cast<T>((std::numeric_limits<int>::min)()));
         check_within_half(static_cast<T>((std::numeric_limits<int>::min)()), si);
         si = boost::math::itrunc(static_cast<T>((std::numeric_limits<int>::max)()));
         check_trunc_result(static_cast<T>((std::numeric_limits<int>::max)()), si);
         si = boost::math::itrunc(static_cast<T>((std::numeric_limits<int>::min)()));
         check_trunc_result(static_cast<T>((std::numeric_limits<int>::min)()), si);
      }
      if(abs(r) < (std::numeric_limits<long>::max)())
      {
         long l = boost::math::lround(arg);
         check_within_half(arg, l);
         l = boost::math::ltrunc(arg);
         check_trunc_result(arg, l);
         r = boost::math::modf(arg, &l);
         check_modf_result(arg, r, l);
      }
      if(std::numeric_limits<T>::digits >= std::numeric_limits<long>::digits)
      {
         long k = boost::math::lround(static_cast<T>((std::numeric_limits<long>::max)()));
         check_within_half(static_cast<T>((std::numeric_limits<long>::max)()), k);
         k = boost::math::lround(static_cast<T>((std::numeric_limits<long>::min)()));
         check_within_half(static_cast<T>((std::numeric_limits<long>::min)()), k);
         k = boost::math::ltrunc(static_cast<T>((std::numeric_limits<long>::max)()));
         check_trunc_result(static_cast<T>((std::numeric_limits<long>::max)()), k);
         k = boost::math::ltrunc(static_cast<T>((std::numeric_limits<long>::min)()));
         check_trunc_result(static_cast<T>((std::numeric_limits<long>::min)()), k);
      }

#ifdef BOOST_HAS_LONG_LONG
      if(abs(r) < (std::numeric_limits<boost::long_long_type>::max)())
      {
         boost::long_long_type ll = boost::math::llround(arg);
         check_within_half(arg, ll);
         ll = boost::math::lltrunc(arg);
         check_trunc_result(arg, ll);
         r = boost::math::modf(arg, &ll);
         check_modf_result(arg, r, ll);
      }
      if(std::numeric_limits<T>::digits >= std::numeric_limits<boost::long_long_type>::digits)
      {
         boost::long_long_type j = boost::math::llround(static_cast<T>((std::numeric_limits<boost::long_long_type>::max)()));
         check_within_half(static_cast<T>((std::numeric_limits<boost::long_long_type>::max)()), j);
         j = boost::math::llround(static_cast<T>((std::numeric_limits<boost::long_long_type>::min)()));
         check_within_half(static_cast<T>((std::numeric_limits<boost::long_long_type>::min)()), j);
         j = boost::math::lltrunc(static_cast<T>((std::numeric_limits<boost::long_long_type>::max)()));
         check_trunc_result(static_cast<T>((std::numeric_limits<boost::long_long_type>::max)()), j);
         j = boost::math::lltrunc(static_cast<T>((std::numeric_limits<boost::long_long_type>::min)()));
         check_trunc_result(static_cast<T>((std::numeric_limits<boost::long_long_type>::min)()), j);
      }
#endif
   }
   //
   // Finish off by testing the error handlers:
   //
   BOOST_CHECK_THROW(boost::math::iround(static_cast<T>(1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::iround(static_cast<T>(-1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::lround(static_cast<T>(1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::lround(static_cast<T>(-1e20)), boost::math::rounding_error);
#ifdef BOOST_HAS_LONG_LONG
   BOOST_CHECK_THROW(boost::math::llround(static_cast<T>(1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::llround(static_cast<T>(-1e20)), boost::math::rounding_error);
#endif
   if(std::numeric_limits<T>::has_infinity)
   {
      BOOST_CHECK_THROW(boost::math::round(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::iround(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::iround(-std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::lround(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::lround(-std::numeric_limits<T>::infinity()), boost::math::rounding_error);
   #ifdef BOOST_HAS_LONG_LONG
      BOOST_CHECK_THROW(boost::math::llround(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::llround(-std::numeric_limits<T>::infinity()), boost::math::rounding_error);
   #endif
   }
   if(std::numeric_limits<T>::has_quiet_NaN)
   {
      BOOST_CHECK_THROW(boost::math::round(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::iround(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::lround(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
   #ifdef BOOST_HAS_LONG_LONG
      BOOST_CHECK_THROW(boost::math::llround(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
   #endif
   }
   BOOST_CHECK_THROW(boost::math::itrunc(static_cast<T>(1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::itrunc(static_cast<T>(-1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::ltrunc(static_cast<T>(1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::ltrunc(static_cast<T>(-1e20)), boost::math::rounding_error);
#ifdef BOOST_HAS_LONG_LONG
   BOOST_CHECK_THROW(boost::math::lltrunc(static_cast<T>(1e20)), boost::math::rounding_error);
   BOOST_CHECK_THROW(boost::math::lltrunc(static_cast<T>(-1e20)), boost::math::rounding_error);
#endif
   if(std::numeric_limits<T>::has_infinity)
   {
      BOOST_CHECK_THROW(boost::math::trunc(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::itrunc(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::itrunc(-std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::ltrunc(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::ltrunc(-std::numeric_limits<T>::infinity()), boost::math::rounding_error);
   #ifdef BOOST_HAS_LONG_LONG
      BOOST_CHECK_THROW(boost::math::lltrunc(std::numeric_limits<T>::infinity()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::lltrunc(-std::numeric_limits<T>::infinity()), boost::math::rounding_error);
   #endif
   }
   if(std::numeric_limits<T>::has_quiet_NaN)
   {
      BOOST_CHECK_THROW(boost::math::trunc(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::itrunc(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::ltrunc(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
   #ifdef BOOST_HAS_LONG_LONG
      BOOST_CHECK_THROW(boost::math::lltrunc(std::numeric_limits<T>::quiet_NaN()), boost::math::rounding_error);
   #endif
   }
   if(std::numeric_limits<T>::digits >= std::numeric_limits<int>::digits)
   {
      BOOST_CHECK_THROW(boost::math::itrunc(static_cast<T>((std::numeric_limits<int>::max)()) + 1), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::itrunc(static_cast<T>((std::numeric_limits<int>::min)()) - 1), boost::math::rounding_error);
   }
   if(std::numeric_limits<T>::digits >= std::numeric_limits<long>::digits)
   {
      BOOST_CHECK_THROW(boost::math::ltrunc(static_cast<T>((std::numeric_limits<long>::max)()) + 1), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::ltrunc(static_cast<T>((std::numeric_limits<long>::min)()) - 1), boost::math::rounding_error);
   }
#ifndef BOOST_NO_LONG_LONG
   if(std::numeric_limits<T>::digits >= std::numeric_limits<boost::long_long_type>::digits)
   {
      BOOST_CHECK_THROW(boost::math::lltrunc(static_cast<T>((std::numeric_limits<boost::long_long_type>::max)()) + 1), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::lltrunc(static_cast<T>((std::numeric_limits<boost::long_long_type>::min)()) - 1), boost::math::rounding_error);
   }
#endif
   if(std::numeric_limits<T>::digits >= std::numeric_limits<int>::digits)
   {
      BOOST_CHECK_THROW(boost::math::iround(static_cast<T>((std::numeric_limits<int>::max)()) + 1), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::iround(static_cast<T>((std::numeric_limits<int>::min)()) - 1), boost::math::rounding_error);
   }
   if(std::numeric_limits<T>::digits >= std::numeric_limits<long>::digits)
   {
      BOOST_CHECK_THROW(boost::math::lround(static_cast<T>((std::numeric_limits<long>::max)()) + 1), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::lround(static_cast<T>((std::numeric_limits<long>::min)()) - 1), boost::math::rounding_error);
   }
#ifndef BOOST_NO_LONG_LONG
   if(std::numeric_limits<T>::digits >= std::numeric_limits<boost::long_long_type>::digits)
   {
      BOOST_CHECK_THROW(boost::math::llround(static_cast<T>((std::numeric_limits<boost::long_long_type>::max)()) + 1), boost::math::rounding_error);
      BOOST_CHECK_THROW(boost::math::llround(static_cast<T>((std::numeric_limits<boost::long_long_type>::min)()) - 1), boost::math::rounding_error);
   }
#endif
}

int test_main(int, char* [])
{
   test_round(0.1F, "float");
   test_round(0.1, "double");
#ifndef BOOST_MATH_NO_LONG_DOUBLE_MATH_FUNCTIONS
   test_round(0.1L, "long double");
   test_round(boost::math::concepts::real_concept(0.1), "real_concept");
#else
   std::cout << "<note>The long double tests have been disabled on this platform "
      "either because the long double overloads of the usual math functions are "
      "not available at all, or because they are too inaccurate for these tests "
      "to pass.</note>" << std::cout;
#endif
   return 0;
}





