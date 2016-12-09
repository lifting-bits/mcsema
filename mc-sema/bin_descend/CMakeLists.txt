
#add_custom_target(get_cfg_py ALL
#  ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/get_cfg.py ${BIN_DESCEND_PATH}/#get_cfg.py
#  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/CFG_pb2.py #${BIN_DESCEND_PATH}/CFG_pb2.py
#  SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/get_cfg.py ${CMAKE_CURRENT_SOURCE_DIR}/CFG_pb2.py
#  WORKING_DIRECTORY ${BIN_DESCEND_PATH})
#
#add_custom_target(fake_imports_py ALL
#  ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/fake_imports.py ${BIN_DESCEND_PATH}#/fake_imports.py
#  SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/fake_imports.py
#  WORKING_DIRECTORY ${BIN_DESCEND_PATH}
#
#add_custom_target(imports_for_dll_py ALL
#  ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/imports_for_dll.py #${BIN_DESCEND_PATH}/imports_for_dll.py
#  SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/imports_for_dll.py
#  WORKING_DIRECTORY ${BIN_DESCEND_PATH}
#  )
#