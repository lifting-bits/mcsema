#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#
boost_additional_test_dependencies(statechart BOOST_DEPENDS test numeric)



macro(statechart_compile_fail TESTNAME)
  boost_test_compile_fail("${TESTNAME}Normal"
    ${TESTNAME}.cpp
    )
  boost_test_compile_fail("${TESTNAME}Native"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_STATECHART_USE_NATIVE_RTTI"
    )
  boost_test_compile_fail("${TESTNAME}Relaxed"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_STATECHART_RELAX_TRANSITION_CONTEXT"
    )
  boost_test_compile_fail("${TESTNAME}Both"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_STATECHART_USE_NATIVE_RTTI -DBOOST_STATECHART_RELAX_TRANSITION_CONTEXT"
    )
endmacro(statechart_compile_fail)

macro(statechart_run TESTNAME)
  boost_test_run("${TESTNAME}Normal"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_DISABLE_THREADS"
    DEPENDS boost_test_exec_monitor
    )
  boost_test_run("${TESTNAME}Native"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_DISABLE_THREADS -DBOOST_STATECHART_USE_NATIVE_RTTI"
    DEPENDS boost_test_exec_monitor
    )
  boost_test_run("${TESTNAME}Relaxed"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_DISABLE_THREADS -DBOOST_STATECHART_RELAX_TRANSITION_CONTEXT"
    DEPENDS boost_test_exec_monitor
    )
  boost_test_run("${TESTNAME}Both"
    ${TESTNAME}.cpp
    COMPILE_FLAGS "-DBOOST_DISABLE_THREADS -DBOOST_STATECHART_USE_NATIVE_RTTI -DBOOST_STATECHART_RELAX_TRANSITION_CONTEXT"
    DEPENDS boost_test_exec_monitor
    )
endmacro(statechart_run)


statechart_compile_fail(InvalidChartTest1)
statechart_compile_fail(InvalidChartTest2)
statechart_compile_fail(InvalidChartTest3)
statechart_run(TransitionTest)
statechart_compile_fail(InvalidTransitionTest1)
statechart_compile_fail(InvalidTransitionTest2)
statechart_run(InStateReactionTest)
statechart_run(TerminationTest)
statechart_run(DeferralTest)
statechart_run(CustomReactionTest)
statechart_compile_fail(InvalidResultAssignTest)
statechart_compile_fail(InvalidResultDefCtorTest)
statechart_run(InvalidResultCopyTest)
statechart_run(UnconsumedResultTest)
statechart_run(HistoryTest)
statechart_compile_fail(InconsistentHistoryTest1)
statechart_compile_fail(InconsistentHistoryTest2)
statechart_compile_fail(InconsistentHistoryTest3)
statechart_compile_fail(InconsistentHistoryTest4)
statechart_compile_fail(InconsistentHistoryTest5)
statechart_compile_fail(InconsistentHistoryTest6)
statechart_compile_fail(InconsistentHistoryTest7)
statechart_compile_fail(InconsistentHistoryTest8)
statechart_compile_fail(UnsuppDeepHistoryTest)
statechart_run(StateCastTest)
statechart_run(TypeInfoTest)
statechart_run(StateIterationTest)
statechart_run(FifoSchedulerTest)

message(STATUS "Statechart Testing needs intermediate libraries created")
# TODO: We need to create some libraries (just for testing!?), then link
# and run tests against them. Ick.
#statechart-st-lib-run LibTestNormal
#  : TuTestMain : TuTest : <link>static $(normal))
#statechart-st-lib-run LibTestNative
#  : TuTestMain : TuTest : <link>static $(native))
#statechart-st-lib-run DllTestNormal
#  : TuTestMain : TuTest : <link>shared $(normal))
#statechart-st-lib-run DllTestNative
#  : TuTestMain : TuTest : <link>shared $(native))

