# ----------------------------------------------------------------------------
# leveldb-mcne
# ----------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.16)

project(leveldb-mcne
  VERSION 1.0.0
  DESCRIPTION "XOR encrypted extension for LevelDB"
  LANGUAGES C CXX)

option(LEVELDB_MCNE_BUILD_TESTS "Build the mcne_test executable" ON)
option(LEVELDB_MCNE_BUILD_BENCH "Build the mcne_benchmark executable" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(LEVELDB_MCNE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/dist"
  CACHE PATH "Directory built libraries and executables are written to")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${LEVELDB_MCNE_OUTPUT_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${LEVELDB_MCNE_OUTPUT_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${LEVELDB_MCNE_OUTPUT_DIR}")

if(WIN32)
  set(LEVELDB_MCNE_DLLX "__declspec(dllexport)")
else()
  set(LEVELDB_MCNE_DLLX "")
endif()

set(ZLIB_BUILD_TESTING OFF CACHE BOOL "Build the zlib tests" FORCE)
set(ZLIB_BUILD_SHARED OFF CACHE BOOL "Build the zlib shared library" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "Build the zlib static library" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "Add zlib install rules" FORCE)
add_subdirectory(deps/zlib EXCLUDE_FROM_ALL)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
add_subdirectory(deps/leveldb-mcpe EXCLUDE_FROM_ALL)

if(WIN32)
  target_compile_definitions(leveldb PUBLIC WIN32)
endif()

add_library(leveldb_mcne STATIC leveldb_mcne.cc)

target_include_directories(leveldb_mcne
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/leveldb-mcpe/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/leveldb-mcpe")

target_compile_definitions(leveldb_mcne PUBLIC "DLLX=${LEVELDB_MCNE_DLLX}")

target_link_libraries(leveldb_mcne
  PUBLIC
    leveldb
    ZLIB::ZLIBSTATIC)

if(LEVELDB_MCNE_BUILD_TESTS)
  add_executable(mcne_test test/mcne_test.cc)
  target_link_libraries(mcne_test PRIVATE leveldb_mcne)
endif()

if(LEVELDB_MCNE_BUILD_BENCH)
  add_executable(mcne_bench test/mcne_bench.cc)
  target_link_libraries(mcne_bench PRIVATE leveldb_mcne)
endif()
