# (C) Copyright 2005: Eric Niebler
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

# bring in rules for testing
#import testing ;
#import feature ;

#feature.feature iterator_debugging
#  : on off
# : composite propagated optional
#  ;

#feature.compose <iterator_debugging>off
#  : <define>_HAS_ITERATOR_DEBUGGING=0
#  ;

# project
#     : requirements
#       <library>/boost/test//boost_unit_test_framework
#       <link>static
#       <include>../../..
#       <toolset>msvc:<define>_SCL_SECURE_NO_DEPRECATE
#       # MSVC's iterator debugging causes some tests to run forever.
#       <toolset>msvc:<iterator_debugging>off
#       <toolset>intel-win:<iterator_debugging>off
#     ;

boost_additional_test_dependencies(accumulators BOOST_DEPENDS test)


set(TESTS 
count
covariance
droppable
error_of
extended_p_square
extended_p_square_quantile
external_accumulator
external_weights
kurtosis
max
mean
median
min
moment
pot_quantile
p_square_cumulative_distribution
p_square_quantile
reference
skewness
sum
tail
tail_mean
tail_quantile
tail_variate_means
valarray
variance
vector
weighted_covariance
weighted_extended_p_square
weighted_kurtosis
weighted_mean
weighted_median
weighted_moment
weighted_p_square_cum_dist
weighted_p_square_quantile
weighted_skewness
weighted_sum
weighted_variance
weighted_pot_quantile
weighted_tail_mean
weighted_tail_quantile
weighted_tail_variate_means)

foreach(TEST ${TESTS})
  boost_test_run(${TEST} DEPENDS boost_unit_test_framework boost_serialization)
endforeach(TEST ${TESTS})

if(WIN32)
  message("Need to turn on iterator debugging")
endif(WIN32)