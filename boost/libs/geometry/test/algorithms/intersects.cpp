// Boost.Geometry (aka GGL, Generic Geometry Library)
//
// Copyright (c) 2007-2012 Barend Gehrels, Amsterdam, the Netherlands.
// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <algorithms/test_intersects.hpp>


#include <boost/geometry/geometries/geometries.hpp>
#include <boost/geometry/geometries/point_xy.hpp>

#include <boost/geometry/util/rational.hpp>


template <typename P>
void test_all()
{
    // intersect <=> ! disjoint
    // so most tests are done in disjoint test.
    // We only test compilation of one case.
    test_geometry<P, bg::model::box<P> >("POINT(1 1)", "BOX(0 0,2 2)", true);

    // self-intersecting is not tested in disjoint, so that is done here.
    typedef bg::model::polygon<P> polygon;

    // Just a normal polygon
    test_self_intersects<polygon>("POLYGON((0 0,0 4,1.5 2.5,2.5 1.5,4 0,0 0))", false);

    // Self intersecting
    test_self_intersects<polygon>("POLYGON((1 2,1 1,2 1,2 2.25,3 2.25,3 0,0 0,0 3,3 3,2.75 2,1 2))", true);

    // Self intersecting in last segment
    test_self_intersects<polygon>("POLYGON((0 2,2 4,2 0,4 2,0 2))", true);

    // Self tangent
    test_self_intersects<polygon>("POLYGON((0 0,0 4,4 4,4 0,2 4,0 0))", true);

    // Self tangent in corner
    test_self_intersects<polygon>("POLYGON((0 0,0 4,4 4,4 0,0 4,2 0,0 0))", true);

    // With spike
    test_self_intersects<polygon>("POLYGON((0 0,0 4,4 4,4 2,6 2,4 2,4 0,0 0))", true);

    // Non intersection, but with duplicate
    test_self_intersects<polygon>("POLYGON((0 0,0 4,4 0,4 0,0 0))", false);

    // With many duplicates
    test_self_intersects<polygon>(
        "POLYGON((0 0,0 1,0 1,0 1,0 2,0 2,0 3,0 3,0 3,0 3,0 4,2 4,2 4,4 4,4 0,4 0,3 0,3 0,3 0,3 0,3 0,0 0))",
        false);

    // Hole: interior tangent to exterior
    test_self_intersects<polygon>("POLYGON((0 0,0 4,4 4,4 0,0 0),(1 2,2 4,3 2,1 2))", true);

    // Hole: interior intersecting exterior
    test_self_intersects<polygon>("POLYGON((0 0,0 4,4 4,4 0,0 0),(1 1,1 3,5 4,1 1))", true);

    // Hole: two intersecting holes
    test_self_intersects<polygon>(
        "POLYGON((0 0,0 4,4 4,4 0,0 0),(1 1,1 3,3 3,3 1,1 1),(2 2,2 3.5,3.5 3.5,3.5 2,2 2))", true);

    // Mail Akira T on [Boost-users] at 27-7-2011 3:17
    test_self_intersects<bg::model::linestring<P> >(
        "LINESTRING(0 0,0 4,4 4,2 2,2 5)", true);

    test_self_intersects<bg::model::linestring<P> >(
        "LINESTRING(0 4,4 4,2 2,2 5)", true);

    // Test self-intersections at last segment in close/open rings:
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,4 1,0 0))", false);

    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,3 3,4 1))", false);

    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,4 1,0 1,0 0))", true);

    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,3 3,4 1,0 1))", true);

    // Duplicates in first or last
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,4 1,0 1,0 1,0 0))", true);
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,4 1,0 1,0 0,0 0))", true);
    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,3 3,4 1,0 1,0 1))", true);
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,0 0,3 3,4 1,0 1,0 1,0 0))", true);
    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,0 0,3 3,4 1,0 1,0 1))", true);
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,3 3,4 1,0 1,0 1,0 0))", true);
    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,3 3,3 3,4 1,0 1,0 1))", true);

    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,4 1,0 0,0 0))", false);
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,4 1,4 1,0 0))", false);
    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,3 3,4 1,4 1))", false);
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,0 0,3 3,4 1,0 0))", false);
    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,0 0,3 3,4 1))", false);
    test_self_intersects<bg::model::ring<P> >(
        "POLYGON((0 0,3 3,3 3,4 1,0 0))", false);
    test_self_intersects<bg::model::ring<P, true, false> >(
        "POLYGON((0 0,3 3,3 3,4 1))", false);
}




int test_main( int , char* [] )
{
    test_all<bg::model::d2::point_xy<double> >();

    test_all<bg::model::d2::point_xy<boost::rational<int> > >();
    

#if defined(HAVE_TTMATH)
    test_all<bg::model::d2::point_xy<ttmath_big> >();
#endif

    return 0;
}
