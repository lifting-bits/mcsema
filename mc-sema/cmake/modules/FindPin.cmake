set(_PIN_NAMES pin)

find_program(PIN_EXECUTABLE
	NAMES ${_PIN_NAMES}
	PATHS "$ENV{PIN_HOME}" "${CMAKE_SOURCE_DIR}/thirdparty/win32/pin/ia32/bin" "C:/pin-2.10-45467-msvc10-ia32_intel64-windows/ia32/bin" "C:/pin/ia32/bin" "/usr/bin" "/opt/bin" "/usr/local/bin" "/bin" "/opt/pin"
	)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Pin REQUIRED_VARS PIN_EXECUTABLE)
mark_as_advanced(PIN_EXECUTABLE)
