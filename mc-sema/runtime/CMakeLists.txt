#add_custom_target(RuntimeCopy ALL COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB cAndBC ${CMAKE_CURRENT_SOURCE_DIR}/*.c ${CMAKE_CURRENT_SOURCE_DIR}/*.bc)
add_custom_target(RuntimeCopy ALL)
foreach(FIL ${cAndBC})
    add_custom_command(TARGET RuntimeCopy COMMAND ${CMAKE_COMMAND} -E copy ${FIL} ${CMAKE_CURRENT_BINARY_DIR})
endforeach()

