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
typedef SDT_CGAL::Site_2 Site_CGAL;

// Include for the Boost.Polygon library.
#include <boost/polygon/polygon.hpp>
typedef boost::polygon::point_data<int32> POINT_POLYGON;
typedef boost::polygon::segment_data<int32> SEGMENT_POLYGON;
typedef std::vector<SEGMENT_POLYGON> SSD_POLYGON;

const int RANDOM_SEED = 27;
const int NUM_TESTS = 6;
const int NUM_SEGMENTS[] = {10, 100, 1000, 10000, 100000, 1000000};
const int NUM_RUNS[] = {100000, 10000, 1000, 100, 10, 1};
std::ofstream bf("benchmark_segments.txt",
                 std::ios_base::out | std::ios_base::app);
boost::timer timer;

void format_line(int num_points, int num_tests, double time_per_test) {
  bf << "| " << std::setw(16) << num_points << " ";
  bf << "| " << std::setw(15) << num_tests << " ";
  bf << "| " << std::setw(17) << time_per_test << " ";
  bf << "|" << std::endl;
}

void clean_segment_set(std::vector<SEGMENT_POLYGON> &data) {
  typedef int32 Unit;
  typedef boost::polygon::scanline_base<Unit>::Point Point;
  typedef boost::polygon::scanline_base<Unit>::half_edge half_edge;
  typedef int segment_id;
  std::vector<std::pair<half_edge, segment_id> > half_edges;
  std::vector<std::pair<half_edge, segment_id> > half_edges_out;
  segment_id id = 0;
  half_edges.reserve(data.size());
  for (std::vector<SEGMENT_POLYGON>::iterator it = data.begin();
       it != data.end(); ++it) {
    POINT_POLYGON l = it->low();
    POINT_POLYGON h = it->high();
    half_edges.push_back(std::make_pair(half_edge(l, h), id++));
  }
  half_edges_out.reserve(half_edges.size());
  // Apparently no need to pre-sort data when calling validate_scan.
  boost::polygon::line_intersection<Unit>::validate_scan(
      half_edges_out, half_edges.begin(), half_edges.end());
  std::vector<SEGMENT_POLYGON> result;
  result.reserve(half_edges_out.size());
  for (std::size_t i = 0; i < half_edges_out.size(); ++i) {
    id = half_edges_out[i].second;
    POINT_POLYGON l = half_edges_out[i].first.first;
    POINT_POLYGON h = half_edges_out[i].first.second;
    SEGMENT_POLYGON orig_seg = data[id];
    if (orig_seg.high() < orig_seg.low())
      std::swap(l, h);
    result.push_back(SEGMENT_POLYGON(l, h));
  }
  std::swap(result, data);
}

std::vector<double> get_intersection_runtime() {
  std::vector<double> running_times;
  boost::mt19937 gen(RANDOM_SEED);
  for (int i = 0; i < NUM_TESTS; ++i) {
    timer.restart();
    for (int j = 0; j < NUM_RUNS[i]; ++j) {
      SSD_POLYGON ssd;
      for (int k = 0; k < NUM_SEGMENTS[i]; ++k) {
        int32 x1 = gen();
        int32 y1 = gen();
        int32 dx = (gen() & 1023) + 1;
        int32 dy = (gen() & 1023) + 1;
        ssd.push_back(SEGMENT_POLYGON(
            POINT_POLYGON(x1, y1), POINT_POLYGON(x1 + dx, y1 + dy)));
      }
      clean_segment_set(ssd);
    }
    running_times.push_back(timer.elapsed());
  }
  return running_times;
}

void run_voronoi_test(const std::vector<double> &running_times) {
  boost::mt19937 gen(RANDOM_SEED);
  bf << "Boost.Polygon Voronoi of Segments:\n";
  for (int i = 0; i < NUM_TESTS; ++i) {
    timer.restart();
    for (int j = 0; j < NUM_RUNS[i]; ++j) {
      SSD_POLYGON ssd;
      VD_BOOST vd;
      for (int k = 0; k < NUM_SEGMENTS[i]; ++k) {
        int32 x1 = gen();
        int32 y1 = gen();
        int32 dx = (gen() & 1023) + 1;
        int32 dy = (gen() & 1023) + 1;
        ssd.push_back(SEGMENT_POLYGON(
            POINT_POLYGON(x1, y1), POINT_POLYGON(x1 + dx, y1 + dy)));
      }
      clean_segment_set(ssd);
      boost::polygon::construct_voronoi(ssd.begin(), ssd.end(), &vd);
    }
    double time_per_test = (timer.elapsed() - running_times[i]) / NUM_RUNS[i];
    format_line(NUM_SEGMENTS[i], NUM_RUNS[i], time_per_test);
  }
  bf << "\n";
}

void run_cgal_test(const std::vector<double> &running_times) {
  boost::mt19937 gen(RANDOM_SEED);
  bf << "CGAL Triangulation of Segments:\n";
  for (int i = 0; i < NUM_TESTS; ++i) {
    timer.restart();
    for (int j = 0; j < NUM_RUNS[i]; ++j) {
      SSD_POLYGON ssd;
      for (int k = 0; k < NUM_SEGMENTS[i]; ++k) {
        int32 x1 = gen();
        int32 y1 = gen();
        int32 dx = (gen() & 1023) + 1;
        int32 dy = (gen() & 1023) + 1;
        ssd.push_back(SEGMENT_POLYGON(POINT_POLYGON(x1, y1),
                                   POINT_POLYGON(x1 + dx, y1 + dy)));
      }
      clean_segment_set(ssd);
      SDT_CGAL dt;
      for (SSD_POLYGON::iterator it = ssd.begin(); it != ssd.end(); ++it) {
        dt.insert(Site_CGAL::construct_site_2(
          Point_CGAL(it->low().x(), it->low().y()),
          Point_CGAL(it->high().x(), it->high().y())));
      }
    }
    double time_per_test = (timer.elapsed() - running_times[i]) / NUM_RUNS[i];
    format_line(NUM_SEGMENTS[i], NUM_RUNS[i], time_per_test);
  }
  bf << "\n";
}

int main() {
  bf << std::setiosflags(std::ios::right | std::ios::fixed)
     << std::setprecision(6);
  std::vector<double> running_times = get_intersection_runtime();
  run_voronoi_test(running_times);
  run_cgal_test(running_times);
  bf.close();
  return 0;
}
