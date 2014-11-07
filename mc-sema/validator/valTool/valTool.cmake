
set(ENV{PIN_HOME} ${PIN_HOME})

if(WIN32)
execute_process(
	COMMAND nmake -f Nmakefile
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	)
else(WIN32)
execute_process(
	COMMAND make -f makefile
	WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	)
endif(WIN32)
