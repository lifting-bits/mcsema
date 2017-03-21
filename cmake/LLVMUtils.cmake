
function(CheckEmitLlvmFlag)
    file(WRITE "${CMAKE_BINARY_DIR}/emitllvm.test.c" "int main(int argc, char* argv[]){return 0;}\n\n")
    file(WRITE "${CMAKE_BINARY_DIR}/emitllvm.test.cpp" "int main(int argc, char* argv[]){return 0;}\n\n")

    message(STATUS "Checking for C LLVM compiler...")
    execute_process(COMMAND "${LLVM_BC_C_COMPILER}" "-emit-llvm" "-c" "emitllvm.test.c" "-o" "emitllvm.test.c.bc"
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                  RESULT_VARIABLE AOUT_IS_NOT_BC
                  OUTPUT_QUIET ERROR_QUIET)
    if(AOUT_IS_NOT_BC)
      message(FATAL_ERROR "${LLVM_BC_C_COMPILER} is not valid LLVM compiler")
    endif()
    message(STATUS "Checking for C LLVM compiler... works: ${LLVM_BC_C_COMPILER}")

    message(STATUS "Checking for CXX LLVM compiler...")
    execute_process(COMMAND "${LLVM_BC_CXX_COMPILER}" "-emit-llvm" "-c" "emitllvm.test.cpp" "-o" "emitllvm.test.cpp.bc"
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                  RESULT_VARIABLE AOUT_IS_NOT_BC
                  OUTPUT_QUIET ERROR_QUIET)
    if(AOUT_IS_NOT_BC)
        message(FATAL_ERROR "${LLVM_BC_CXX_COMPILER} is not valid LLVM compiler")
    endif()
    message(STATUS "Checking for CXX LLVM compiler... works: ${LLVM_BC_CXX_COMPILER}")
endfunction(CheckEmitLlvmFlag)

######################################################################################################
## ADD_BITCODE                                                                                      ##
######################################################################################################

macro(add_bitcode target flags)

    set(bcfiles "")
    foreach(srcfile ${ARGN})
        ## get the definitions, flags, and includes to use when compiling this file
        set(srcdefs "")
        get_directory_property(COMPILE_DEFINITIONS COMPILE_DEFINITIONS)
        foreach(DEFINITION ${COMPILE_DEFINITIONS})
            list(APPEND srcdefs -D${DEFINITION})
        endforeach()


        if(${srcfile} MATCHES "(.*).cpp" OR ${srcfile} MATCHES "(.*).cc")
            separate_arguments(srcflags UNIX_COMMAND ${CMAKE_CXX_FLAGS})
            list(APPEND srcflags "-std=gnu++${CMAKE_CXX_STANDARD}")
            set(src_bc_compiler ${LLVM_BC_CXX_COMPILER})
        else()
            separate_arguments(srcflags UNIX_COMMAND ${CMAKE_C_FLAGS})
            list(APPEND srcflags "-std=gnu${CMAKE_CXX_STANDARD}")
            set(src_bc_compiler ${LLVM_BC_C_COMPILER} )
        endif()
        # include any extra compilation flags
        if(flags)
            list(APPEND srcflags ${flags})
        endif()

        set(srcincludes "")
        get_directory_property(INCLUDE_DIRECTORIES INCLUDE_DIRECTORIES)
        foreach(DIRECTORY ${INCLUDE_DIRECTORIES})
            list(APPEND srcincludes -I${DIRECTORY})
        endforeach()
        
        get_filename_component(outfile ${srcfile} NAME)
        set (outfile "${target}_${srcfile}")

        get_filename_component(infile ${srcfile} ABSOLUTE)

        ## the command to generate the bitcode for this file
        add_custom_command(OUTPUT ${outfile}.bc
          COMMAND ${src_bc_compiler} -emit-llvm ${srcdefs} ${srcflags} ${srcincludes}
            -c ${infile} -o ${outfile}.bc
          DEPENDS ${infile}
          IMPLICIT_DEPENDS CXX ${infile}
          COMMENT "Building LLVM bitcode ${outfile}.bc"
          VERBATIM
        )
        set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${outfile}.bc)

        ## keep track of every bitcode file we need to create
        list(APPEND bcfiles ${outfile}.bc)
    endforeach(srcfile)

    #link all the bitcode files together to the target
    add_custom_command(OUTPUT ${target}.bc
        COMMAND ${LLVM_BC_LINK} ${BC_LD_FLAGS} -o ${CMAKE_CURRENT_BINARY_DIR}/${target}.bc ${bcfiles}
        DEPENDS ${bcfiles}
        COMMENT "Linking LLVM bitcode ${target}.bc"
    )
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${target}.bc)

    # ## build all the bitcode files
    add_custom_target(${target} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${target}.bc)
    set_property(TARGET ${target} PROPERTY LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${target}.bc)

endmacro(add_bitcode)


######################################################################################################
## SETUP                                                                                            ##
######################################################################################################


if (NOT (LLVM_TOOLS_BINARY_DIR))
  message(SEND_ERROR "LLVM_TOOLS_BINARY_DIR must be defined. Did you find_package(LLVM) ?")
endif()

#LLVM_PACKAGE_VERSION has the full 3 digit version number (i.e 3.8.1); we only want 
# the major and minor to find a working toolset
set(LLVM_TO_FIND "${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}")

#try to find tools for this specific LLVM version
find_program(LLVM_BC_C_COMPILER "clang-${LLVM_TO_FIND}" PATH ${LLVM_TOOLS_BINARY_DIR})
find_program(LLVM_BC_CXX_COMPILER "clang++-${LLVM_TO_FIND}" PATH ${LLVM_TOOLS_BINARY_DIR})
find_program(LLVM_BC_LINK "llvm-link-${LLVM_TO_FIND}" PATH ${LLVM_TOOLS_BINARY_DIR})

# back up to non-version-specific toolset
if (NOT LLVM_BC_C_COMPILER)
  message(STATUS "Could not find clang-${LLVM_TO_FIND}, looking for clang")
  find_program(LLVM_BC_C_COMPILER clang PATH ${LLVM_TOOLS_BINARY_DIR})
endif()

if (NOT LLVM_BC_CXX_COMPILER)
  message(STATUS "Could not find clang++-${LLVM_TO_FIND}, looking for clang++")
  find_program(LLVM_BC_CXX_COMPILER clang++ PATH ${LLVM_TOOLS_BINARY_DIR})
endif()

if (NOT LLVM_BC_LINK)
  message(STATUS "Could not find llvm-link-${LLVM_TO_FIND}, looking for llvm-link")
  find_program(LLVM_BC_LINK llvm-link PATH ${LLVM_TOOLS_BINARY_DIR})
endif()

# all attempts at finding working tools failed. error out
if (NOT (LLVM_BC_C_COMPILER AND LLVM_BC_CXX_COMPILER AND LLVM_BC_LINK))
  message(SEND_ERROR "Some of following tools have not been found:")
  if (NOT LLVM_BC_C_COMPILER)
     message(SEND_ERROR "LLVM_BC_C_COMPILER") 
  endif()
  if (NOT LLVM_BC_CXX_COMPILER) 
     message(SEND_ERROR "LLVM_BC_CXX_COMPILER")
  endif()
  if (NOT LLVM_BC_LINK) 
    message(SEND_ERROR "LLVM_BC_LINK")
  endif()
endif()

CheckEmitLlvmFlag()

