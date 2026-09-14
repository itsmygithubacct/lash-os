find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(LASHOS_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
cmake_path(IS_PREFIX LASHOS_SOURCE_ROOT "${CMAKE_BINARY_DIR}" NORMALIZE lashos_in_source)
if(lashos_in_source)
    message(FATAL_ERROR "Configure outside the release checkout; use make or an external -B directory")
endif()
if(NOT DEFINED LASHOS_BUILD_DIR)
    execute_process(COMMAND "${Python3_EXECUTABLE}" -B "${LASHOS_SOURCE_ROOT}/scripts/workspace.py" --get build
                    OUTPUT_VARIABLE LASHOS_BUILD_DIR OUTPUT_STRIP_TRAILING_WHITESPACE
                    COMMAND_ERROR_IS_FATAL ANY)
endif()
