if(NOT DEFINED BURNER_SOURCE_DIR)
    message(FATAL_ERROR "BURNER_SOURCE_DIR is required")
endif()

if(NOT DEFINED BURNER_REDIST_DIR)
    message(FATAL_ERROR "BURNER_REDIST_DIR is required")
endif()

file(MAKE_DIRECTORY "${BURNER_REDIST_DIR}")

if(NOT DEFINED BURNER_COPY_TO_SOURCE_DIR)
    set(BURNER_COPY_TO_SOURCE_DIR ON)
endif()

set(burner_runtime_dlls)

if(DEFINED BURNER_RUNTIME_DLL_FILES AND NOT BURNER_RUNTIME_DLL_FILES STREQUAL "")
    list(APPEND burner_runtime_dlls ${BURNER_RUNTIME_DLL_FILES})
endif()

if(DEFINED BURNER_RUNTIME_DLL_DIRS AND NOT BURNER_RUNTIME_DLL_DIRS STREQUAL "")
    foreach(runtime_dir IN LISTS BURNER_RUNTIME_DLL_DIRS)
        if(EXISTS "${runtime_dir}")
            file(GLOB runtime_dir_dlls "${runtime_dir}/*.dll")
            list(APPEND burner_runtime_dlls ${runtime_dir_dlls})
        endif()
    endforeach()
endif()

file(GLOB burner_source_dir_dlls "${BURNER_SOURCE_DIR}/*.dll")
list(APPEND burner_runtime_dlls ${burner_source_dir_dlls})
list(REMOVE_DUPLICATES burner_runtime_dlls)

foreach(runtime_dll IN LISTS burner_runtime_dlls)
    if(EXISTS "${runtime_dll}")
        if(BURNER_COPY_TO_SOURCE_DIR)
            file(COPY "${runtime_dll}" DESTINATION "${BURNER_SOURCE_DIR}")
        endif()
        file(COPY "${runtime_dll}" DESTINATION "${BURNER_REDIST_DIR}")
    endif()
endforeach()
