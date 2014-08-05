# Copyright (C) 2008 The Trustees of Indiana University.
#
# Use, modification and distribution is subject to the Boost Software
# License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

set(PBGL_DOCS
  DistributedGraph             
  DistributedEdgeListGraph     
  DistributedVertexListGraph   
  GlobalDescriptor             
  boman_et_al_graph_coloring   
  breadth_first_search         
  connected_components         
  dehne_gotz_min_spanning_tree 
  dijkstra_example             
  dijkstra_shortest_paths      
  distributed_adjacency_list   
  distributed_property_map     
  distributed_queue            
  distributedS                 
  index                        
  local_subgraph               
  metis                        
  overview                     
  page_rank                    
  process_group                
  mpi_bsp_process_group
  simple_trigger               
  strong_components            
  tsin_depth_first_visit       
  vertex_list_adaptor
  rmat_generator
  sorted_rmat_generator
  unique_rmat_generator
  sorted_unique_rmat_generator
  scalable_rmat_generator
  mesh_generator
  ssca_generator
  fruchterman_reingold
  st_connected
  betweenness_centrality
  connected_components_parallel_search
  )

set(PBGL_IMAGES
  dijkstra_dist3_graph.png dijkstra_seq_graph.png vertex_coloring.png
  architecture.png dist-adjlist.png dist-pmap.png distributed-graph.png
  graph.png)

set(PBGL_DOC_TARGETS)
separate_arguments(RST2HTML_FLAGS)
foreach(DOC ${PBGL_DOCS})
  add_custom_command(OUTPUT "${PBGL_BINARY_DIR}/libs/graph_parallel/doc/${DOC}.html"
    COMMAND "${RST2HTML}" 
    ARGS ${RST2HTML_FLAGS} "${PBGL_SOURCE_DIR}/libs/graph_parallel/doc/${DOC}.rst"
         "${PBGL_BINARY_DIR}/libs/graph/doc/parallel/${DOC}.html"
    COMMENT "Generating document ${DOC}.html..."
    )
  list(APPEND PBGL_DOC_TARGETS "${PBGL_BINARY_DIR}/libs/graph_parallel/doc/${DOC}.html")
endforeach(DOC)

add_custom_target(doc ALL
  DEPENDS ${PBGL_DOC_TARGETS})

install(FILES ${PBGL_DOC_TARGETS} ${PBGL_IMAGES}
  DESTINATION "doc/pbgl-${PBGL_VERSION}"
  COMPONENT "Documentation"
  OPTIONAL
  )
