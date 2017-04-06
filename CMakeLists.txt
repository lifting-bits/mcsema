# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)

include_directories(${PROJECT_SOURCE_DIR})

add_executable(mcsema-lift
  EXCLUDE_FROM_ALL
  generated/CFG.pb.cc
  mcsema/Arch/Arch.cpp
  mcsema/CFG/CFG.cpp
  mcsema/BC/External.cpp
  mcsema/BC/Function.cpp
  mcsema/BC/Instruction.cpp
  mcsema/BC/Lift.cpp
  mcsema/BC/Optimize.cpp
  mcsema/BC/Segment.cpp
  mcsema/BC/Util.cpp
  mcsema/Lift.cpp
)

add_dependencies(mcsema-lift
  semantics
)

target_link_libraries(mcsema-lift
  remill
)

#install(
#  TARGETS mcsema-lift 
#  RUNTIME DESTINATION bin
#  LIBRARY DESTINATION lib)
