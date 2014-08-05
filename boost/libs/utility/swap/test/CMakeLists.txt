#
# Copyright Troy D. Straszheim
#
# Distributed under the Boost Software License, Version 1.0.
# See http://www.boost.org/LICENSE_1_0.txt
#

foreach(T 
    root_header_1 root_header_2 
    lib_header_1 lib_header_2 
    mixed_headers_1 mixed_headers_2)
  boost_test_compile(${T})
endforeach() 


#     [ run primitive.cpp ../../../test/build//boost_test_exec_monitor/<link>static                      ]


foreach(T
    primitive
    specialized_in_boost
    specialized_in_global
    specialized_in_other
    specialized_in_std
    specialized_in_boost_and_other
    std_bitset
    std_dateorder
    std_string
    std_typeinfo_ptr
    std_vector_of_boost
    std_vector_of_global
    std_vector_of_other
    no_ambiguity_in_boost
    array_of_array_of_class
    array_of_array_of_int
    array_of_class
    array_of_int
    array_of_template)
  boost_test_run(${T} DEPENDS boost_test_exec_monitor)
endforeach()
    
