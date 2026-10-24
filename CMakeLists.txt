cmake_minimum_required(VERSION 3.22.1)
project(vpnengine LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build only the static Zstandard library; the resulting vpnengine.so embeds it.
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "Do not build zstd command-line tools" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "Do not build zstd tests" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "Do not build zstd contrib tools" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "Do not build libzstd.so separately" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "Build static libzstd" FORCE)
set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "Build single-threaded zstd library" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "Disable legacy zstd formats" FORCE)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/zstd/build/cmake/CMakeLists.txt")
    message(FATAL_ERROR
        "Zstandard source not found. Expected zstd/build/cmake/CMakeLists.txt "
        "next to zvpn_jni.c. Put this CMakeLists.txt in your zvpn-client folder.")
endif()

add_subdirectory(
    "${CMAKE_CURRENT_SOURCE_DIR}/zstd/build/cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/zstd-build"
)

add_library(vpnengine SHARED "${CMAKE_CURRENT_SOURCE_DIR}/zvpn_jni.c")
target_include_directories(vpnengine PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/zstd/lib")
target_link_libraries(vpnengine PRIVATE libzstd_static log)

# Keep the Android library's expected name: System.loadLibrary("vpnengine").
set_target_properties(vpnengine PROPERTIES OUTPUT_NAME "vpnengine")
