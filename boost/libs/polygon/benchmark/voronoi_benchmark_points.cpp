// Boost.Polygon library voronoi_benchmark.cpp file

//          Copyright Andrii Sydorchuk 2010-2012.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

// See http://www.boost.org for updates, documentation, and revision history.

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <numeric>
#include <vector>
#include <utility>

#include <boost/random/mersenne_twister.hpp>
#include <boost/timer.hpp>

typedef boost::int32_t int32;

// Include for the Boost.Polygon Voronoi library.
#include <boost/polygon/voronoi.hpp>
typedef boost::polygon::default_voronoi_builder VB_BOOST;
typedef boost::polygon::voronoi_diagram<double> VD_BOOST;

// Includes for the CGAL library.
#include <CGAL/Quotient.h>
#include <CGAL/MP_Float.h>
#include <CGAL/Simple_cartesian.h>
#include <CGAL/Segment_Delaunay_graph_filtered_traits_2.h>
#include <CGAL/Segment_Delaunay_graph_2.h>
typedef CGAL::Quotient<CGAL::MP_Float> ENT;
typedef CGAL::Simple_cartesian<double> CK;
typedef CGAL::Simple_cartesian<ENT> EK;
typedef CGAL::Segment_Delaunay_graph_filtered_traits_2<
    CK, CGAL::Field_with_sqrt_tag, EK, CGAL::Field_tag> Gt;
typedef CGAL::Segment_Delaunay_graph_2<Gt> SDT_CGAL;
typedef SDT_CGAL::Point_2 Point_CGAL;

// Includes for the S-Hull library.
#include <s_hull.h>

const int RANDOM_SEED = 27;
const int NUM_TESTS = 6;
const int NUM_POINTS[] = {10, 100, 1000, 10000, 100000, 1000000};
const int NUM_RUNS[] = {100000, 10000, 1000, 100, 10, 1};
std::ofstream bf("benchmark_points.txt",
                 std::ios_base::out | std::ios_base::app);
boost::timer timer;

void format_line(int num_points, int num_tests, double time_per_test) {
  bf << "| " << std::setw(16) << num_points << " ";
  bf << "| " << std::setw(15) << num_tests << " ";
  bf << "| " << std::setw(17) << time_per_test << " ";
  bf << "|" << std::endl;
}

void run_boost_test() {
  boost::mt19937 gen(RANDOM_SEED);
  bf << "Boost.Polygon Voronoi of Points:\n";
  for (int i = 0; i < NUM_TESTS; ++i) {
    timer.restart();
    for (int j = 0; j < NUM_RUNS[i]; ++j) {
      VB_BOOST vb;
      VD_BOOST vd;
      for (int k = 0; k < NUM_POINTS[i]; ++k)
        vb.insert_point(static_cast<int32>(gen()), static_cast<int32>(gen()));
      vb.construct(&vd);
    }
    double time_per_test = timer.elapsed() / NUM_RUNS[i];
    format_line(NUM_POINTS[i], NUM_RUNS[i], time_per_test);
  }
  bf << "\n";
}

void run_cgal_test() {
  boost::mt19937 gen(RANDOM_SEED);
  bf << "CGAL Triangulation of Points:\n";
  for (int i = 0; i < NUM_TESTS; ++i) {
    timer.restart();
    for (int j = 0; j < NUM_RUNS[i]; ++j) {
      SDT_CGAL dt;
      for (int k = 0; k < NUM_POINTS[i]; ++k) {
        dt.insert(Point_CGAL(
            static_cast<int32>(gen()), static_cast<int32>(gen())));
      }
    }
    double time_per_test = timer.elapsed() / NUM_RUNS[i];
    format_line(NUM_POINTS[i], NUM_RUNS[i], time_per_test);
  }
  bf << "\n";
}

void run_shull_test() {
  boost::mt19937 gen(RANDOM_SEED);
  bf << "S-Hull Triangulation of Points:\n";
  // This value is required by S-Hull as it doesn't seem to support properly
  // coordinates with the absolute value higher than 100.
  float koef = 100.0 / (1 << 16) / (1 << 15);
  for (int i = 0; i < NUM_TESTS; ++i) {
    timer.restart();
    for (int j = 0; j < NUM_RUNS[i]; ++j) {
      // S-Hull doesn't deal properly with duplicates so we need
      // to eliminate them before running the algorithm.
      std::vector< pair<int32, int32> > upts;
      std::vector<Shx> pts;
      std::vector<Triad> triads;
      Shx pt;
      for (int k = 0; k < NUM_POINTS[i]; ++k) {
        int32 x = static_cast<int32>(gen());
        int32 y = static_cast<int32>(gen());
        upts.push_back(std::make_pair(x, y));
      }
      // Absolutely the same code is used by the Boost.Polygon Voronoi library.
      std::sort(upts.begin(), upts.end());
      upts.erase(std::unique(upts.begin(), upts.end()), upts.end());
      for (int k = 0; k < upts.size(); ++k) {
        pt.r = koef * upts[k].first;
        pt.c = koef * upts[k].second;
        pt.id = k;
        pts.push_back(pt);
      }
      s_hull_del_ray2(pts, triads);
    }
    double time_per_test = timer.elapsed() / NUM_RUNS[i];
    format_line(NUM_POINTS[i], NUM_RUNS[i], time_per_test);
  }
  bf << "\n";
}

int main() {
  bf << std::setiosflags(std::ios::right | std::ios::fixed)
     << std::setprecision(6);
  run_boost_test();
  run_cgal_test();
  run_shull_test();
  bf.close();
  return 0;
}
