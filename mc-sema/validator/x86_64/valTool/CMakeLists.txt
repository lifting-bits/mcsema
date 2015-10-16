find_package(Pin REQUIRED)

get_filename_component(PIN_PATH ${PIN_EXECUTABLE} PATH)

add_custom_target(pin_validate ALL
	COMMAND "${CMAKE_COMMAND}" -DPIN_HOME="${PIN_PATH}" -P "${CMAKE_CURRENT_SOURCE_DIR}/valTool.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
	COMMENT Building PIN tool for validation...
	)

add_dependencies(pin_validate Pin)
