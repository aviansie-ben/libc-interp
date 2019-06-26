cmake_minimum_required(VERSION 3.0)
project("Libc Stub WebAssembly Interpreter" CXX)

add_subdirectory(${WASMJIT_OMR_LOCATION} wasmjit-omr EXCLUDE_FROM_ALL)

add_executable(libc-interp libc-interp.cpp syscall.cpp)
target_link_libraries(libc-interp PRIVATE wabt)
target_include_directories(libc-interp PRIVATE ${WASMJIT_OMR_LOCATION} ${CMAKE_BINARY_DIR}/wasmjit-omr)
set_target_properties(libc-interp PROPERTIES COMPILE_FLAGS "-g -Wall")
