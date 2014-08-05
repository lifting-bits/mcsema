set(_NASM_NAMES nasm nasmw)

find_program(NASM_EXECUTABLE 
	NAMES ${_NASM_NAMES}
	PATHS "${CMAKE_SOURCE_DIR}/thirdparty/win32/nasm" "C:/nasm" "/usr/bin" "/opt/bin" "/usr/local/bin" "/bin"
	)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Nasm REQUIRED_VARS NASM_EXECUTABLE)
mark_as_advanced(NASM_EXECUTABLE)
