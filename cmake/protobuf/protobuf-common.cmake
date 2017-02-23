include_directories( ${PROTOBUF_ROOT}/src )

# Set relative rpath for protoc to be able to find libs after installed
set(CMAKE_INSTALL_RPATH "\$ORIGIN/../lib")

# config.h is generated from cmake now, so use on all platforms
add_definitions( -DHAVE_CONFIG_H )

if( MSVC )
  add_definitions(
    -D_CRT_SECURE_NO_WARNINGS=1
    /wd4244 /wd4267 /wd4018 /wd4355 /wd4800 /wd4251 /wd4996 /wd4146 /wd4305
    )
else()
  add_definitions( -Wno-deprecated )
endif()

# Easier to support different versions of protobufs
function(append_if_exist OUTPUT_LIST)
    set(${OUTPUT_LIST})
    foreach(fil ${ARGN})
        if(EXISTS ${fil})
            list(APPEND ${OUTPUT_LIST} "${fil}")
        else()
            message("Warning: file missing: ${fil}")
        endif()
    endforeach()
    set(${OUTPUT_LIST} ${${OUTPUT_LIST}} PARENT_SCOPE)
endfunction()

# Install locations
set(BIN_DIR     bin)
set(INCLUDE_DIR include)
if(WIN32)
    # On windows .dlls need to be next to the binaries
    # TODO: We don't properly build .dlls
    # http://www.cmake.org/Wiki/BuildingWinDLL
    # NOTE: findprotobuf doesn't work unless this is set to lib
    set(LIB_DIR     lib)
else()
    set(LIB_DIR     lib)
endif()
