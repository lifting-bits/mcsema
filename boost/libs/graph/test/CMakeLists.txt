# Copyright (C) 2008 Michael Jackson
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

boost_additional_test_dependencies(graph BOOST_DEPENDS test assign)

boost_test_run(transitive_closure_test)
boost_test_compile(adj_list_cc)
boost_test_run(adj_list_edge_list_set)
boost_test_compile(adj_matrix_cc)
boost_test_run(bfs)
boost_test_compile(bfs_cc)
boost_test_run(bellman-test)
boost_test_run(betweenness_centrality_test DEPENDS boost_graph SHARED)
boost_test_run(csr_graph_test)
boost_test_run(dag_longest_paths)
boost_test_run(dfs)
boost_test_compile(dfs_cc)
boost_test_compile(dijkstra_cc)
boost_test_run(dijkstra_heap_performance ARGS 10000 DEPENDS boost_graph SHARED)
boost_test_run(dominator_tree_test)
boost_test_run(relaxed_heap_test ARGS 5000 15000)
boost_test_compile(edge_list_cc)
boost_test_compile(filtered_graph_cc)
boost_test_run(generator_test)
boost_test_run(graph)
boost_test_compile(graph_concepts)
boost_test_run(graphviz_test 
  DEPENDS boost_test_exec_monitor boost_graph STATIC)
boost_test_run(gursoy_atun_layout_test)
boost_test_run(layout_test)
boost_test_run(serialize DEPENDS boost_serialization)
boost_test_compile(reverse_graph_cc)
boost_test_run(sequential_vertex_coloring)
boost_test_run(subgraph)
boost_test_run(isomorphism)
boost_test_run(adjacency_matrix_test)
boost_test_compile(vector_graph_cc)
boost_test_compile(copy)
boost_test_compile(property_iter)
boost_test_run(bundled_properties)
boost_test_run(floyd_warshall_test)
boost_test_run(astar_search_test)
boost_test_run(biconnected_components_test)
boost_test_run(cuthill_mckee_ordering)
boost_test_run(king_ordering)
boost_test_run(matching_test)
boost_test_run(mcgregor_subgraphs_test)
# boost_test_run(max_flow_test)
# boost_test_run(kolmogorov_max_flow_test) TODO: Boost 1.34.x only

# GraphML Tests - not for Boost 1.34.x
#include(FindEXPAT)
#if (EXPAT_FOUND)
#  include_directories(${EXPAT_INCLUDE_DIRS})
#  boost_test_run(graphml_test LIBRARIES boost_graph)
#endif (EXPAT_FOUND)

# Stanford GraphBase Tests
if ($ENV{SDB})
  include_directories("$ENV{SDB}")
  boost_test_compile(stanford_graph_cc)
endif ($ENV{SDB})

# LEDA tests
if ($ENV{LEDA})
  include_directories("$ENV{LEDA}/incl")
  boost_test_compile(leda_graph_cc)
endif ($ENV{LEDA}) 
