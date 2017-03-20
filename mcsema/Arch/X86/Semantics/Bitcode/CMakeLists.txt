# manually list every file that goes into the semantics targets.
# There are ways to do a glob(),but they require cmake to be manually 
# re-run.
# This method is the recommended approach for adding multiple source files
set(SEMANTICS_TARGETS
    FXAM.cpp
    )

add_bitcode(
    mcsema_semantics_x86
    "-m32"
    ${SEMANTICS_TARGETS})
set_target_properties( mcsema_semantics_x86 PROPERTIES TYPE "STATIC_LIBRARY")
install(
    FILES $<TARGET_PROPERTY:mcsema_semantics_x86,LOCATION>
    DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")

add_bitcode(
    mcsema_semantics_amd64
    "-m64"
    ${SEMANTICS_TARGETS})
install(
    FILES $<TARGET_PROPERTY:mcsema_semantics_amd64,LOCATION>
    DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
