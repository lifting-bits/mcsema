include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../parser-library)

add_executable( dump-prog 
                dump.cpp )

target_link_libraries(  dump-prog 
                        pe-parser-library )
