if(NOT DEFINED BURNER_SOURCE_DIR)
    message(FATAL_ERROR "BURNER_SOURCE_DIR is required")
endif()

if(NOT DEFINED BURNER_REDIST_DIR)
    message(FATAL_ERROR "BURNER_REDIST_DIR is required")
endif()

file(MAKE_DIRECTORY "${BURNER_REDIST_DIR}")

file(GLOB burner_runtime_dlls "${BURNER_SOURCE_DIR}/*.dll")
foreach(runtime_dll IN LISTS burner_runtime_dlls)
    file(COPY "${runtime_dll}" DESTINATION "${BURNER_REDIST_DIR}")
endforeach()
