
set(ENV{PIN_HOME} ${PIN_HOME})

if(WIN32)
execute_process(
	COMMAND nmake -f Nmakefile
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	)
else(WIN32)
	if(APPLE)
		execute_process(
			COMMAND make -f Makefile.osx
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
			)
	else(APPLE)
		execute_process(
			COMMAND make -f Makefile.linux
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
			)
	endif(APPLE)
endif(WIN32)
