cmake_minimum_required(VERSION 3.24)
project(LinuxBashOSPortable LANGUAGES C)
set(CMAKE_C_STANDARD 17)
get_filename_component(LINUX_BASH_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
include("${LINUX_BASH_ROOT}/cmake/Workspace.cmake")
set(CAPSULE_INCLUDE_DIRECTORY "" CACHE PATH "Headers from the pinned Capsule SDK")
set(BASH_SKELETON_DIRECTORY "${LASHOS_BUILD_DIR}/kernel-full" CACHE PATH "Verified full-image skeleton")
if(NOT EXISTS "${CAPSULE_INCLUDE_DIRECTORY}/bpf_capsule_host.h" OR
   NOT EXISTS "${BASH_SKELETON_DIRECTORY}/bash.skel.h")
    message(FATAL_ERROR "Use make portable to prepare the SDK and full-image skeleton")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf>=1.4.0)
add_compile_options(-O2 -Wall -Wextra)
# Build-machine directories must not reach __FILE__ or debug records in the shipped loader.
add_compile_options("-ffile-prefix-map=${LINUX_BASH_ROOT}=/lashos/source"
                    "-ffile-prefix-map=${LASHOS_BUILD_DIR}=/lashos/build")
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_compile_options(-march=x86-64 -mtune=generic)
endif()
add_link_options(-static -no-pie)
include_directories("${LINUX_BASH_ROOT}/include" "${CAPSULE_INCLUDE_DIRECTORY}")

# Compile the workspace's host implementation against musl. No native SDK
# archive is linked: that archive was compiled against the regular host libc.
add_executable(linux-bash-os
    "${LINUX_BASH_ROOT}/src/host.c"
    "${LINUX_BASH_ROOT}/src/sandbox_host.c"
    "${LINUX_BASH_ROOT}/vendor/capsule-host/bpf_capsule_host.c")
file(STRINGS "${LINUX_BASH_ROOT}/VERSION" LASHOS_VERSION LIMIT_COUNT 1)
target_compile_definitions(linux-bash-os PRIVATE LASHOS_VERSION="${LASHOS_VERSION}")
target_include_directories(linux-bash-os PRIVATE
    "${BASH_SKELETON_DIRECTORY}" ${LIBBPF_STATIC_INCLUDE_DIRS})
target_compile_options(linux-bash-os PRIVATE ${LIBBPF_STATIC_CFLAGS_OTHER})
target_link_directories(linux-bash-os PRIVATE ${LIBBPF_STATIC_LIBRARY_DIRS})
target_link_options(linux-bash-os PRIVATE ${LIBBPF_STATIC_LDFLAGS_OTHER})
target_link_libraries(linux-bash-os PRIVATE ${LIBBPF_STATIC_LIBRARIES} zstd)
add_executable(sandbox-init "${LINUX_BASH_ROOT}/src/sandbox_init.c")

include(CTest)
if(BUILD_TESTING)
    foreach(test queued-signals poll inherited-fds syscall-abi bridge-abi)
        add_executable(${test}-test "${LINUX_BASH_ROOT}/tests/${test}.c")
        target_compile_options(${test}-test PRIVATE -UNDEBUG -Wno-unused-function -Wno-unused-variable)
        add_test(NAME ${test} COMMAND ${test}-test)
        set_tests_properties(${test} PROPERTIES TIMEOUT 5)
    endforeach()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_executable(sandbox-test "${LINUX_BASH_ROOT}/tests/sandbox.c")
    target_compile_options(sandbox-test PRIVATE -UNDEBUG)
    target_link_libraries(sandbox-test PRIVATE zstd)
    add_test(NAME sandbox COMMAND sandbox-test)
    set_tests_properties(sandbox PROPERTIES TIMEOUT 5)
    add_test(NAME source-tree COMMAND ${Python3_EXECUTABLE} "${LINUX_BASH_ROOT}/tests/source-tree.py")
    add_test(NAME workspace COMMAND ${Python3_EXECUTABLE} -B "${LINUX_BASH_ROOT}/tests/workspace.py")
    add_executable(job-control-test "${LINUX_BASH_ROOT}/tests/job-control.c")
    add_executable(sandbox-launch-policy "${LINUX_BASH_ROOT}/tests/sandbox-launch-policy.c")
endif()
install(TARGETS linux-bash-os RUNTIME DESTINATION bin)
