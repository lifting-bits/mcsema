foreach(example 

    monitor
    starvephil
    # tennis  this doesn't build on linux for some stupid reason
    condition
    mutex
    once
    recursive_mutex
    thread
    thread_group
    tss
    xtime)

  boost_add_executable(${example} DEPENDS boost_thread MULTI_THREADED)

endforeach()