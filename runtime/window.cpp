#define SDL_MAIN_HANDLED

#include "window.h"

#include <cstdio>

#if defined(ARC_HAVE_SDL2)
#include <SDL2/SDL.h>
#endif

namespace arc {
namespace {

#if defined(ARC_HAVE_SDL2)
SDL_Window* g_window = nullptr;
SDL_GLContext g_context = nullptr;
#endif
int g_width = 0, g_height = 0;
bool g_open = false;
Touch g_pending;

}  // namespace

bool WindowOpen(int width, int height, const char* title) {
#if defined(ARC_HAVE_SDL2)
  if (g_open) return true;
  SDL_SetMainReady();
  if (SDL_Init(SDL_INIT_VIDEO) != 0) {
    std::printf("window: SDL would not start: %s\n", SDL_GetError());
    return false;
  }
  // A compatibility profile, deliberately. The guest is fixed-function GLES
  // 1.1 -- matrix stack, client arrays, no shaders -- and a core profile has
  // none of that. This is the whole reason the GL shims are one-liners.
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK,
                      SDL_GL_CONTEXT_PROFILE_COMPATIBILITY);
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
  SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 16);
  g_window = SDL_CreateWindow(title ? title : "iparecomp",
                              SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                              width, height, SDL_WINDOW_OPENGL);
  if (!g_window) {
    std::printf("window: could not create one: %s\n", SDL_GetError());
    return false;
  }
  g_context = SDL_GL_CreateContext(g_window);
  if (!g_context) {
    std::printf("window: no GL context: %s\n", SDL_GetError());
    return false;
  }
  SDL_GL_SetSwapInterval(1);
  g_width = width;
  g_height = height;
  g_open = true;
  return true;
#else
  (void)title;
  g_width = width;
  g_height = height;
  return false;
#endif
}

bool WindowIsOpen() { return g_open; }
int WindowWidth() { return g_width; }
int WindowHeight() { return g_height; }

bool WindowPresent() {
#if defined(ARC_HAVE_SDL2)
  if (!g_open) return false;
  SDL_GL_SwapWindow(g_window);
  SDL_Event e;
  while (SDL_PollEvent(&e)) {
    switch (e.type) {
      case SDL_QUIT:
        g_open = false;
        break;
      case SDL_KEYDOWN:
        if (e.key.keysym.sym == SDLK_ESCAPE) g_open = false;
        break;
      // The mouse stands in for a finger. Canabalt takes one touch and only
      // ever asks whether it began, so this is the whole input surface.
      case SDL_MOUSEBUTTONDOWN:
        g_pending = {Touch::kBegan, float(e.button.x), float(e.button.y), true};
        break;
      case SDL_MOUSEBUTTONUP:
        g_pending = {Touch::kEnded, float(e.button.x), float(e.button.y), true};
        break;
      case SDL_MOUSEMOTION:
        if (e.motion.state)
          g_pending = {Touch::kMoved, float(e.motion.x), float(e.motion.y),
                       true};
        break;
      default:
        break;
    }
  }
  return g_open;
#else
  return false;
#endif
}

Touch WindowTakeTouch() {
  const Touch t = g_pending;
  g_pending.valid = false;
  return t;
}

void WindowClose() {
#if defined(ARC_HAVE_SDL2)
  if (g_context) SDL_GL_DeleteContext(g_context);
  if (g_window) SDL_DestroyWindow(g_window);
  g_context = nullptr;
  g_window = nullptr;
  if (g_open) SDL_Quit();
#endif
  g_open = false;
}

}  // namespace arc
