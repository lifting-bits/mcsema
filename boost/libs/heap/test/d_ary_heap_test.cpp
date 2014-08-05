#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include <algorithm>

#include <boost/heap/d_ary_heap.hpp>

#include "common_heap_tests.hpp"
#include "stable_heap_tests.hpp"
#include "mutable_heap_tests.hpp"
#include "merge_heap_tests.hpp"


template <int D, bool stable>
void run_d_ary_heap_test(void)
{
    typedef boost::heap::d_ary_heap<int, boost::heap::arity<D>,
                                         boost::heap::stable<stable>,
                                         boost::heap::compare<std::less<int> >,
                                         boost::heap::allocator<std::allocator<int> > > pri_queue;

    BOOST_CONCEPT_ASSERT((boost::heap::PriorityQueue<pri_queue>));

    run_concept_check<pri_queue>();
    run_common_heap_tests<pri_queue>();
    run_iterator_heap_tests<pri_queue>();
    run_copyable_heap_tests<pri_queue>();
    run_moveable_heap_tests<pri_queue>();
    run_reserve_heap_tests<pri_queue>();
    run_merge_tests<pri_queue>();

    run_ordered_iterator_tests<pri_queue>();

    if (stable) {
        typedef boost::heap::d_ary_heap<q_tester, boost::heap::arity<D>,
                                                  boost::heap::stable<stable>
                                       > stable_pri_queue;

        run_stable_heap_tests<stable_pri_queue>();
    }
}


BOOST_AUTO_TEST_CASE( d_ary_heap_test )
{
    run_d_ary_heap_test<2, false>();
    run_d_ary_heap_test<3, false>();
    run_d_ary_heap_test<4, false>();
    run_d_ary_heap_test<5, false>();
}

BOOST_AUTO_TEST_CASE( d_ary_heap_stable_test )
{
    run_d_ary_heap_test<2, true>();
    run_d_ary_heap_test<3, true>();
    run_d_ary_heap_test<4, true>();
    run_d_ary_heap_test<5, true>();
}

template <int D, bool stable>
void run_d_ary_heap_mutable_test(void)
{
    typedef boost::heap::d_ary_heap<int, boost::heap::mutable_<true>,
                                            boost::heap::arity<D>,
                                            boost::heap::stable<stable>
                                           > pri_queue;

    BOOST_CONCEPT_ASSERT((boost::heap::MutablePriorityQueue<pri_queue>));

    run_common_heap_tests<pri_queue>();
    run_moveable_heap_tests<pri_queue>();
    run_reserve_heap_tests<pri_queue>();
    run_mutable_heap_tests<pri_queue>();

    run_merge_tests<pri_queue>();

    run_ordered_iterator_tests<pri_queue>();

    if (stable) {
        typedef boost::heap::d_ary_heap<q_tester, boost::heap::mutable_<true>,
                                                boost::heap::arity<D>,
                                                boost::heap::stable<stable>
                                               > stable_pri_queue;
        run_stable_heap_tests<stable_pri_queue>();
    }
}

BOOST_AUTO_TEST_CASE( d_ary_heap_mutable_test )
{
    run_d_ary_heap_mutable_test<2, false>();
    run_d_ary_heap_mutable_test<3, false>();
    run_d_ary_heap_mutable_test<4, false>();
    run_d_ary_heap_mutable_test<5, false>();
}

BOOST_AUTO_TEST_CASE( d_ary_heap_mutable_stable_test )
{
    run_d_ary_heap_mutable_test<2, true>();
    run_d_ary_heap_mutable_test<3, true>();
    run_d_ary_heap_mutable_test<4, true>();
    run_d_ary_heap_mutable_test<5, true>();
}
