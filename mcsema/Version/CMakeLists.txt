# Based on: https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin
# Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
# 
# Define the two required variables before including
# the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "Version.cpp.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
set(GIT_WORKING_DIR "${MCSEMA_SOURCE_DIR}")
include("${MCSEMA_SOURCE_DIR}/cmake/git_watcher.cmake")

# Create a library out of the compiled post-configure file.
add_library(McSemaVersion STATIC ${POST_CONFIGURE_FILE})
target_include_directories(McSemaVersion PUBLIC ${MCSEMA_SOURCE_DIR})
add_dependencies(McSemaVersion check_git_${PROJECT_NAME})
