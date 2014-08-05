//=======================================================================
// Copyright 2001 Jeremy G. Siek, Andrew Lumsdaine, Lie-Quan Lee, 
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//=======================================================================
#include <boost/config.hpp>
#include <iostream>
#include <fstream>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>

using namespace boost;

int
main(int, char *[])
{
  typedef adjacency_list_traits<listS, listS, 
    directedS>::vertex_descriptor vertex_descriptor;
  typedef adjacency_list < listS, listS, directedS,
    property<vertex_index_t, int, 
    property<vertex_name_t, char,
    property<vertex_distance_t, int,
    property<vertex_predecessor_t, vertex_descriptor> > > >, 
    property<edge_weight_t, int> > graph_t;
  typedef graph_traits<graph_t>::edge_descriptor edge_descriptor;
  typedef std::pair<int, int> Edge;

  const int num_nodes = 5;
  enum nodes { A, B, C, D, E };
  Edge edge_array[] = { Edge(A, C), Edge(B, B), Edge(B, D), Edge(B, E),
    Edge(C, B), Edge(C, D), Edge(D, E), Edge(E, A), Edge(E, B)
  };
  int weights[] = { 1, 2, 1, 2, 7, 3, 1, 1, 1 };
  int num_arcs = sizeof(edge_array) / sizeof(Edge);
  graph_traits<graph_t>::vertex_iterator i, iend;

#if defined(BOOST_MSVC) && BOOST_MSVC <= 1300
  graph_t g(num_nodes);
  property_map<graph_t, edge_weight_t>::type weightmap = get(edge_weight, g);

  std::vector<vertex_descriptor> msvc_vertices;
  for (boost::tie(i, iend) = vertices(g); i != iend; ++i)
    msvc_vertices.push_back(*i);

  for (std::size_t j = 0; j < num_arcs; ++j) {
    edge_descriptor e; bool inserted;
    boost::tie(e, inserted) = add_edge(msvc_vertices[edge_array[j].first], 
                                       msvc_vertices[edge_array[j].second], g);
    weightmap[e] = weights[j];
  }

#else
  graph_t g(edge_array, edge_array + num_arcs, weights, num_nodes);
  property_map<graph_t, edge_weight_t>::type weightmap = get(edge_weight, g);
#endif

  // Manually intialize the vertex index and name maps
  property_map<graph_t, vertex_index_t>::type indexmap = get(vertex_index, g);
  property_map<graph_t, vertex_name_t>::type name = get(vertex_name, g);
  int c = 0;
  for (boost::tie(i, iend) = vertices(g); i != iend; ++i, ++c) {
    indexmap[*i] = c;
    name[*i] = 'A' + c;
  }

  vertex_descriptor s = vertex(A, g);

  property_map<graph_t, vertex_distance_t>::type
    d = get(vertex_distance, g);
  property_map<graph_t, vertex_predecessor_t>::type
    p = get(vertex_predecessor, g);
#if defined(BOOST_MSVC) && BOOST_MSVC <= 1300
  // VC++ has trouble with the named parameters mechanism
  property_map<graph_t, vertex_index_t>::type indexmap = get(vertex_index, g);
  dijkstra_shortest_paths(g, s, p, d, weightmap, indexmap, 
                          std::less<int>(), closed_plus<int>(), 
                          (std::numeric_limits<int>::max)(), 0,
                          default_dijkstra_visitor());
#else
  dijkstra_shortest_paths(g, s, predecessor_map(p).distance_map(d));
#endif

  std::cout << "distances and parents:" << std::endl;
  graph_traits < graph_t >::vertex_iterator vi, vend;
  for (boost::tie(vi, vend) = vertices(g); vi != vend; ++vi) {
    std::cout << "distance(" << name[*vi] << ") = " << d[*vi] << ", ";
    std::cout << "parent(" << name[*vi] << ") = " << name[p[*vi]] << std::
      endl;
  }
  std::cout << std::endl;

  std::ofstream dot_file("figs/dijkstra-eg.dot");
  dot_file << "digraph D {\n"
    << "  rankdir=LR\n"
    << "  size=\"4,3\"\n"
    << "  ratio=\"fill\"\n"
    << "  edge[style=\"bold\"]\n" << "  node[shape=\"circle\"]\n";

  graph_traits < graph_t >::edge_iterator ei, ei_end;
  for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei) {
    graph_traits < graph_t >::edge_descriptor e = *ei;
    graph_traits < graph_t >::vertex_descriptor
      u = source(e, g), v = target(e, g);
    dot_file << name[u] << " -> " << name[v]
      << "[label=\"" << get(weightmap, e) << "\"";
    if (p[v] == u)
      dot_file << ", color=\"black\"";
    else
      dot_file << ", color=\"grey\"";
    dot_file << "]";
  }
  dot_file << "}";
  return EXIT_SUCCESS;
}
