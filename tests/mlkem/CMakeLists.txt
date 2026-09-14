cmake_minimum_required(VERSION 3.24)
project(LinuxBashMlkemTest LANGUAGES C)
set(CMAKE_C_STANDARD 17)
find_package(BpfCapsule CONFIG REQUIRED)
get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include("${ROOT}/cmake/Codegen.cmake")
include("${ROOT}/cmake/Workspace.cmake")
set(GNU_SOURCE "${LASHOS_BUILD_DIR}/native-full/source/build/bash-5.3")
set(CODEGEN_OPTIONS "" CACHE STRING "LLVM code generation options")
bpf_capsule_object(mlkem_bpf OUTPUT bash.bpf.o SOURCES guest.c check.c
    BITCODE "${LASHOS_BUILD_DIR}/full-bitcode/builtins/_libssh_libcrux_mlkem768_sha3.bc"
    INCLUDE_DIRECTORIES "${ROOT}/include/guest" "${ROOT}/include" "${GNU_SOURCE}/builtins" "${GNU_SOURCE}"
    COMPILE_OPTIONS -g -D_GNU_SOURCE
    LINK_OPTIONS -mcpu=v4 --memory=arena --managed-atomics --allocator-lock=atomic --inline-limit=25
                 --native-shift63 --disable-ldsx --freplace --fiber-stack=2097152 --bpf-capsule-verbose
                 ${linux_bash_codegen_options} ${CODEGEN_OPTIONS})
bpf_capsule_skeleton(mlkem_skeleton OUTPUT mlkem.skel.h OBJECT "${mlkem_bpf}" NAME mlkem)
add_executable(linux-bash-os host.c)
target_link_libraries(linux-bash-os PRIVATE BpfCapsule::host mlkem_skeleton)
add_executable(native-check native.c check.c "${GNU_SOURCE}/builtins/_libssh_libcrux_mlkem768_sha3.o")
target_include_directories(native-check PRIVATE "${GNU_SOURCE}/builtins" "${GNU_SOURCE}")
