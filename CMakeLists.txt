cmake_minimum_required(VERSION 3.20)
project(iparecomp C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W4)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra)
endif()

# The reusable half: Mach-O loader, framework shims, ObjC runtime, host window.
# A port links this and supplies only its own bundle-specific bridge.
add_library(iparecomp STATIC
  runtime/macho_image.cpp
  runtime/arm32_runtime.c
)
target_include_directories(iparecomp PUBLIC runtime)

if(WIN32)
  target_link_libraries(iparecomp PUBLIC ws2_32)
endif()

find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  target_link_libraries(iparecomp PUBLIC ZLIB::ZLIB)
  target_compile_definitions(iparecomp PUBLIC ARC_HAVE_ZLIB)
  message(STATUS "iparecomp: zlib found")
else()
  message(STATUS "iparecomp: no zlib -- those imports stay on the work list")
endif()

find_package(SDL2 CONFIG QUIET)
if(SDL2_FOUND)
  target_link_libraries(iparecomp PUBLIC
    $<TARGET_NAME_IF_EXISTS:SDL2::SDL2>
    $<TARGET_NAME_IF_EXISTS:SDL2::SDL2main>)
  target_compile_definitions(iparecomp PUBLIC ARC_HAVE_SDL2)
  message(STATUS "iparecomp: SDL2 found -- window enabled")
else()
  message(STATUS "iparecomp: no SDL2 -- headless, no window")
endif()

# Standalone triage tool. Ports usually build their own host instead.
if(PROJECT_IS_TOP_LEVEL OR NOT DEFINED PROJECT_IS_TOP_LEVEL)
  add_executable(ipa_host tools/ipa_host.cpp)
  target_link_libraries(ipa_host PRIVATE iparecomp)
endif()

# The context header's shifter and flag helpers, checked against real ARM
# semantics. Cheap, and the failures it catches are silent ones.
add_executable(arc_selftest tools/arc_selftest.c)
target_include_directories(arc_selftest PRIVATE runtime)
enable_testing()
add_test(NAME arc_selftest COMMAND arc_selftest)
