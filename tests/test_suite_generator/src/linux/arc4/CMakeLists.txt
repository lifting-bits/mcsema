project(arc4)
cmake_minimum_required(VERSION 3.2)

set(PROJECT_CXXFLAGS -Wall -Werror)

set(PROJECT_SOURCEFILES
  arc4.h
  arc4.cpp

  main.cpp
)

GenerateTest(${PROJECT_NAME}
  SOURCES ${PROJECT_SOURCEFILES}
  CXXFLAGS ${PROJECT_CXXFLAGS}
)
