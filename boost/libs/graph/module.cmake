boost_module(graph DEPENDS property_map tuple multi_index any random parameter regex)
boost_module(graph_mpi DEPENDS mpi graph)

# any is there because of the dependency on boost/property_map/dynamic_property_map.hpp
