# ----------------------------------------------------------------------------
# FindZLIB.cmake - project local replacement for the CMake module of the same
# name.
#
# deps/leveldb-mcpe resolves its zlib dependency with find_package(ZLIB
# REQUIRED), which searches for a system zlib. That search either fails on
# Windows or, worse, finds a copy that does not match the zlib built from
# deps/zlib. The top level CMakeLists.txt prepends cmake/ to
# CMAKE_MODULE_PATH, so this module is used instead and simply forwards to the
# in-tree target.
#
# The zlib project() call stores zlib_SOURCE_DIR / zlib_BINARY_DIR as cache
# variables, which makes them readable here even though deps/zlib has already
# been processed. zconf.h is generated into the binary directory, hence both
# directories are handed out as include directories.
# ----------------------------------------------------------------------------

if(TARGET ZLIB::ZLIBSTATIC)
  set(ZLIB_LIBRARIES ZLIB::ZLIBSTATIC)
  # Callers commonly link against ZLIB::ZLIB. Only the static library is built
  # here, so alias it - unless the zlib project already created that target.
  if(NOT TARGET ZLIB::ZLIB)
    add_library(ZLIB::ZLIB ALIAS zlibstatic)
  endif()
else()
  set(ZLIB_LIBRARIES ZLIB::ZLIB)
endif()

set(ZLIB_INCLUDE_DIRS "${zlib_SOURCE_DIR}" "${zlib_BINARY_DIR}")
set(ZLIB_INCLUDE_DIR "${zlib_SOURCE_DIR}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZLIB DEFAULT_MSG ZLIB_LIBRARIES ZLIB_INCLUDE_DIRS)
