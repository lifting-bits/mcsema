project(xz_amd64)
cmake_minimum_required(VERSION 3.2)

set(PROJECT_CXXFLAGS -Wall -Werror)
set(PROJECT_LINKERFLAGS -lm -ldl -llzma -lpthread)

AddBinaryTest(${PROJECT_NAME}
  BINARY ${PROJECT_NAME}
  ARCHITECTURE amd64
  CXXFLAGS ${PROJECT_CXXFLAGS}
  LINKERFLAGS ${PROJECT_LINKERFLAGS}
)
