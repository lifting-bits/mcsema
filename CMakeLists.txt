# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
  SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
endif(WIN32)

set(CMAKE_MODULE_PATH "${LLVM_DIR}/cmake/modules ${CMAKE_MODULE_PATH}")

# Configure with the build LLVM
find_package(LLVM 3.8 REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})

# Get protobufs.
if(WIN32)
  # Change the slashes to Unix style or risk the wrath of invalid escape
  # sequences!
  string(REGEX REPLACE "\\\\" "/" MCSEMA_DIR ${MCSEMA_DIR})

  set(PROTOBUF_ROOT "${MCSEMA_DIR}/third_party/protobuf")
  set(Protobuf_LIBRARIES "${PROTOBUF_ROOT}/build/libprotobuf/Release")
  set(Protobuf_INCLUDE_DIR "${PROTOBUF_ROOT}/src")
  
  include_directories(${Protobuf_INCLUDE_DIR})
  link_directories(${Protobuf_LIBRARIES})
elseif(APPLE)
  set(PROTOBUF_ROOT "${MCSEMA_DIR}/third_party/protobuf")
  set(Protobuf_LIBRARIES "${PROTOBUF_ROOT}/build/lib")
  set(Protobuf_INCLUDE_DIR "${PROTOBUF_ROOT}/src")
  
  include_directories(${Protobuf_INCLUDE_DIR})
  link_directories(${Protobuf_LIBRARIES})
endif(WIN32)
find_package(Protobuf REQUIRED)

include_directories(${MCSEMA_DIR})
include_directories(${MCSEMA_DIR}/third_party)
include_directories(${MCSEMA_LLVM_DIR})
include_directories(${MCSEMA_LLVM_DIR}/include)
include_directories(${MCSEMA_LLVM_DIR}/lib/Target/X86/)
include_directories(${MCSEMA_BUILD_DIR}/include)
include_directories(${MCSEMA_BUILD_DIR}/llvm/include)
include_directories(${MCSEMA_BUILD_DIR}/llvm/lib/Target/X86)
include_directories(${MCSEMA_GEN_DIR})

# Make sure we can find the mcsema headers.
include_directories(${MCSEMA_DIR}/mcsema)
include_directories(${MCSEMA_DIR}/mcsema/binary_common)
include_directories(${MCSEMA_DIR}/mcsema/cfgToLLVM)
include_directories(${MCSEMA_DIR}/mcsema/common)
include_directories(${MCSEMA_DIR}/mcsema/peToCFG)
include_directories(${MCSEMA_DIR}/mcsema/cfgToLLVM)

if(WIN32)
  add_compile_options(
    /nologo
    /DGOOGLE_PROTOBUF_NO_RTTI
    /W3
    /wd4141 # Suppress ''modifier' : used more than once' (because of __forceinline combined with inline)
    /wd4146 # Suppress 'unary minus operator applied to unsigned type, result still unsigned'
    /wd4180 # Suppress 'qualifier applied to function type has no meaning; ignored'
    /wd4244 # Suppress ''argument' : conversion from 'type1' to 'type2', possible loss of data'
    /wd4258 # Suppress ''var' : definition from the for loop is ignored; the definition from the enclosing scope is used'
    /wd4267 # Suppress ''var' : conversion from 'size_t' to 'type', possible loss of data'
    /wd4291 # Suppress ''declaration' : no matching operator delete found; memory will not be freed if initialization throws an exception'
    /wd4345 # Suppress 'behavior change: an object of POD type constructed with an initializer of the form () will be default-initialized'
    /wd4351 # Suppress 'new behavior: elements of array 'array' will be default initialized'
    /wd4355 # Suppress ''this' : used in base member initializer list'
    /wd4456 # Suppress 'declaration of 'var' hides local variable'
    /wd4457 # Suppress 'declaration of 'var' hides function parameter'
    /wd4458 # Suppress 'declaration of 'var' hides class member'
    /wd4459 # Suppress 'declaration of 'var' hides global declaration'
    /wd4503 # Suppress ''identifier' : decorated name length exceeded, name was truncated'
    /wd4624 # Suppress ''derived class' : destructor could not be generated because a base class destructor is inaccessible'
    /wd4722 # Suppress 'function' : destructor never returns, potential memory leak
    /wd4800 # Suppress ''type' : forcing value to bool 'true' or 'false' (performance warning)'
    /wd4100 # Suppress 'unreferenced formal parameter'
    /wd4127 # Suppress 'conditional expression is constant'
    /wd4512 # Suppress 'assignment operator could not be generated'
    /wd4505 # Suppress 'unreferenced local function has been removed'
    /wd4610 # Suppress '<class> can never be instantiated'
    /wd4510 # Suppress 'default constructor could not be generated'
    /wd4702 # Suppress 'unreachable code'
    /wd4245 # Suppress 'signed/unsigned mismatch'
    /wd4706 # Suppress 'assignment within conditional expression'
    /wd4310 # Suppress 'cast truncates constant value'
    /wd4701 # Suppress 'potentially uninitialized local variable'
    /wd4703 # Suppress 'potentially uninitialized local pointer variable'
    /wd4389 # Suppress 'signed/unsigned mismatch'
    /wd4611 # Suppress 'interaction between '_setjmp' and C++ object destruction is non-portable'
    /wd4805 # Suppress 'unsafe mix of type <type> and type <type> in operation'
    /wd4204 # Suppress 'nonstandard extension used : non-constant aggregate initializer'
    /wd4577 # Suppress 'noexcept used with no exception handling mode specified; termination on exception is not guaranteed'
    /wd4091 # Suppress 'typedef: ignored on left of '' when no variable is declared'
        # C4592 is disabled because of false positives in Visual Studio 2015
        # Update 1. Re-evaluate the usefulness of this diagnostic with Update 2.
    /wd4592 # Suppress ''var': symbol will be dynamically initialized (implementation limitation)

	# Ideally, we'd like this warning to be enabled, but MSVC 2013 doesn't
	# support the 'aligned' attribute in the way that clang sources requires (for
	# any code that uses the LLVM_ALIGNAS macro), so this is must be disabled to
	# avoid unwanted alignment warnings.
	# When we switch to requiring a version of MSVC that supports the 'alignas'
	# specifier (MSVC 2015?) this warning can be re-enabled.
    /wd4324 # Suppress 'structure was padded due to __declspec(align())'
    /D_CRT_SECURE_NO_DEPRECATE
    /D_CRT_SECURE_NO_WARNINGS
    /D_CRT_NONSTDC_NO_DEPRECATE
    /D_CRT_NONSTDC_NO_WARNINGS
    /D_SCL_SECURE_NO_DEPRECATE
    /D_SCL_SECURE_NO_WARNINGS
    )
else()
  add_compile_options(
    -g3
    -O0
    -std=gnu++11
    -fno-rtti
    -DGOOGLE_PROTOBUF_NO_RTTI)
endif(WIN32)

add_executable(mcsema-lift
  ${MCSEMA_DIR}/mcsema/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/Arch.cpp
  
  ${MCSEMA_DIR}/mcsema/Arch/X86/Dispatch.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Lift.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Register.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Util.cpp

  ${MCSEMA_DIR}/mcsema/BC/Lift.cpp
  ${MCSEMA_DIR}/mcsema/BC/Util.cpp
  ${MCSEMA_DIR}/mcsema/CFG/CFG.cpp
  ${MCSEMA_DIR}/generated/CFG.pb.cc

  ${MCSEMA_DIR}/mcsema/cfgToLLVM/JumpTables.cpp
  ${MCSEMA_DIR}/mcsema/cfgToLLVM/TransExcn.cpp

  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/ADD.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/bitops.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Branches.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/CMOV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/CMPTEST.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Exchanges.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/fpu.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/INCDECNEG.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Jcc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Misc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/MOV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/MULDIV.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SETcc.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/ShiftRoll.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SSE.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/Stack.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/String.cpp
  ${MCSEMA_DIR}/mcsema/Arch/X86/Semantics/SUB.cpp)

target_link_libraries(mcsema-lift
  protobuf
  LLVMBitReader
  LLVMBitWriter
  LLVMMCDisassembler
  LLVMX86Disassembler
  LLVMX86AsmParser
  LLVMX86CodeGen
  LLVMSelectionDAG
  LLVMAsmPrinter
  LLVMX86Desc
  LLVMX86Info
  LLVMX86AsmPrinter
  LLVMX86Utils
  LLVMipo
  LLVMTransformUtils
  LLVMScalarOpts
  LLVMInstrumentation
  LLVMObjCARCOpts)

install(
  TARGETS mcsema-lift
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib)
