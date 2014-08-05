#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(msm BOOST_DEPENDS test)

ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB) # -DBOOST_MSM_STATIC_LINK

SET(TESTS
  Anonymous AnonymousEuml 
  CompositeEuml CompositeMachine Constructor
  Entries History 
  OrthogonalDeferred OrthogonalDeferred2 OrthogonalDeferredEuml
  SimpleEuml SimpleEuml2 SimpleInternal SimpleInternalEuml 
  SimpleInternalFunctors SimpleMachine SimpleWithFunctors)

FOREACH(test ${TESTS})
  boost_test_run(${test} 
	${test}.cpp
	DEPENDS boost_unit_test_framework STATIC
	COMPILE_FLAGS -ftemplate-depth-300 -g0
	)
ENDFOREACH(test ${TESTS})
