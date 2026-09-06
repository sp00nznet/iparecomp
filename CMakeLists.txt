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
  runtime/objc_runtime.cpp
  runtime/arc_mem.cpp
  runtime/shim_libsystem.cpp
  runtime/objc_host.cpp
  runtime/shim_foundation.cpp
  runtime/shim_objects.cpp
  runtime/shim_uikit.cpp
  runtime/shim_gl.cpp
  runtime/shim_audio.cpp
  runtime/shim_coregraphics.cpp
  runtime/shim_image.cpp
  runtime/window.cpp
  runtime/arc_boot.cpp
)
target_include_directories(iparecomp PUBLIC runtime)

if(WIN32)
  target_link_libraries(iparecomp PUBLIC ws2_32)
endif()

# Decoding a PNG is the last place to be inventive, and libpng is already
# here. Without it the bundle's 73 images cannot be read and the game runs
# with nothing on screen.
find_package(PNG QUIET)
if(NOT PNG_FOUND)
  # CMake's own finder only looks in the system prefixes, which on an MSYS2 or
  # Homebrew toolchain is not where libpng is. pkg-config knows.
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(PNG_PC QUIET libpng)
  endif()
endif()
if(PNG_FOUND)
  target_link_libraries(iparecomp PUBLIC PNG::PNG)
  target_compile_definitions(iparecomp PUBLIC ARC_HAVE_PNG)
  message(STATUS "iparecomp: libpng found -- bundle images will load")
elseif(PNG_PC_FOUND)
  target_include_directories(iparecomp PUBLIC ${PNG_PC_INCLUDE_DIRS})
  target_link_libraries(iparecomp PUBLIC ${PNG_PC_LIBRARIES})
  target_link_directories(iparecomp PUBLIC ${PNG_PC_LIBRARY_DIRS})
  target_compile_definitions(iparecomp PUBLIC ARC_HAVE_PNG)
  message(STATUS "iparecomp: libpng ${PNG_PC_VERSION} via pkg-config")
else()
  message(STATUS "iparecomp: no libpng -- images cannot be decoded")
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
  # SDL2 only, never SDL2main: that library exists to rename an application's
  # `main` to `SDL_main`, and iparecomp is a library whose hosts define their
  # own entry point. Linking it drags in a WinMain that then cannot find the
  # SDL_main it was written to call.
  target_link_libraries(iparecomp PUBLIC $<TARGET_NAME_IF_EXISTS:SDL2::SDL2>)
  # The GL the guest wants is OpenGL 1.1, which the system library exports
  # directly -- no loader, no extensions. That is why the GL shims are calls
  # rather than a translation layer.
  find_package(OpenGL)
  if(OPENGL_FOUND)
    target_link_libraries(iparecomp PUBLIC OpenGL::GL)
    message(STATUS "iparecomp: OpenGL found -- GLES 1.1 maps straight onto it")
  endif()
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
