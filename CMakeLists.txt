cmake_minimum_required(VERSION 3.9)
project(injectit)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(external/asm_utils)

include_directories(external/asm_utils/src)
link_directories(lib)

file(GLOB_RECURSE SOURCES
    src/*.h
	src/*.asm
    src/*.cpp
)

string(REGEX REPLACE "[^;]*CMakeFiles/[^;]+;?" "" SOURCES "${SOURCES}")

add_executable(injectitx64 ${SOURCES})
target_link_libraries(injectitx64 asm_utils)
