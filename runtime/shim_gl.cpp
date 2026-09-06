// OpenGL ES 1.1, answered by desktop OpenGL.
//
// This is the part of the port the platform gives away. Every entry point the
// game uses is also OpenGL 1.1 under the same name and the same semantics, so
// these are calls rather than translations, and `opengl32` alone resolves them
// -- no extension loading anywhere. An emulator would be implementing the
// PowerVR MBX here instead, which is the single strongest argument for
// recompiling rather than emulating this era.
//
// Two things do need doing.
//
// Arguments arrive in the wrong registers for C. iOS on armv6 passes floats in
// the integer registers at a public boundary, so `glClearColor` is four words
// in r0-r3 that have to be read back as floats. Getting that wrong produces a
// picture rather than a crash, which is worse.
//
// And the framebuffer object is not real. The guest builds an FBO with a
// renderbuffer to draw into and then presents it; here it draws straight into
// the window's own framebuffer, so the OES calls answer plausibly and bind
// zero. That keeps one copy out of every frame and needs no extensions.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "arm32_context.h"
#include "macho_image.h"
#include "window.h"

#if defined(ARC_HAVE_SDL2)
#include <SDL2/SDL_opengl.h>
#endif

namespace arc {
namespace {

#if defined(ARC_HAVE_SDL2)

// The i-th argument, counting from zero: r0-r3, then the stack. Every shim
// here reads its arguments this way rather than through a C signature,
// because the guest's are not where a C compiler would look for them.
uint32_t A(Arm32Ctx* c, int i) {
  if (i < 4) return ARC_R(c, uint32_t(i));
  return ARC_LD32(ARC_SP(c) + uint32_t(i - 4) * 4);
}

float Af(Arm32Ctx* c, int i) {
  const uint32_t bits = A(c, i);
  float f;
  std::memcpy(&f, &bits, 4);
  return f;
}

// The guest's pointers are host pointers, so a client array goes straight
// through. This is the payoff for mapping the image at its link address.
const void* Ap(Arm32Ctx* c, int i) {
  return reinterpret_cast<const void*>(uintptr_t(A(c, i)));
}

// --- state -----------------------------------------------------------------
void GlEnable(Arm32Ctx* c) { glEnable(A(c, 0)); }
void GlDisable(Arm32Ctx* c) { glDisable(A(c, 0)); }
void GlEnableClientState(Arm32Ctx* c) { glEnableClientState(A(c, 0)); }
void GlDisableClientState(Arm32Ctx* c) { glDisableClientState(A(c, 0)); }
void GlBlendFunc(Arm32Ctx* c) { glBlendFunc(A(c, 0), A(c, 1)); }
void GlClear(Arm32Ctx* c) { glClear(A(c, 0)); }
void GlClearColor(Arm32Ctx* c) {
  glClearColor(Af(c, 0), Af(c, 1), Af(c, 2), Af(c, 3));
}
void GlViewport(Arm32Ctx* c) {
  glViewport(int(A(c, 0)), int(A(c, 1)), int(A(c, 2)), int(A(c, 3)));
}
void GlGetIntegerv(Arm32Ctx* c) {
  glGetIntegerv(A(c, 0), reinterpret_cast<GLint*>(uintptr_t(A(c, 1))));
}

// --- matrices --------------------------------------------------------------
void GlMatrixMode(Arm32Ctx* c) { glMatrixMode(A(c, 0)); }
void GlLoadIdentity(Arm32Ctx*) { glLoadIdentity(); }
void GlPushMatrix(Arm32Ctx*) { glPushMatrix(); }
void GlPopMatrix(Arm32Ctx*) { glPopMatrix(); }
void GlTranslatef(Arm32Ctx* c) { glTranslatef(Af(c, 0), Af(c, 1), Af(c, 2)); }
void GlScalef(Arm32Ctx* c) { glScalef(Af(c, 0), Af(c, 1), Af(c, 2)); }
void GlRotatef(Arm32Ctx* c) {
  glRotatef(Af(c, 0), Af(c, 1), Af(c, 2), Af(c, 3));
}

// glOrthof is the one name desktop GL does not share: it takes doubles there.
void GlOrthof(Arm32Ctx* c) {
  glOrtho(Af(c, 0), Af(c, 1), Af(c, 2), Af(c, 3), Af(c, 4), Af(c, 5));
}

// --- arrays and drawing ----------------------------------------------------
const void* g_vp = nullptr;

void GlVertexPointer(Arm32Ctx* c) {
  g_vp = Ap(c, 3);
  glVertexPointer(int(A(c, 0)), A(c, 1), int(A(c, 2)), Ap(c, 3));
}
void GlTexCoordPointer(Arm32Ctx* c) {
  glTexCoordPointer(int(A(c, 0)), A(c, 1), int(A(c, 2)), Ap(c, 3));
}
void GlColorPointer(Arm32Ctx* c) {
  glColorPointer(int(A(c, 0)), A(c, 1), int(A(c, 2)), Ap(c, 3));
}
// ARC_TRACE_DRAW=1 prints where each of the first few quads actually lands, in
// window pixels, having pushed its vertices through the modelview, the
// projection and the viewport. A list of matrix calls is something to reason
// about; a corner at (-380, -552) is an answer.
void GlDrawArrays(Arm32Ctx* c) {
  static int shown = 0;
  if (std::getenv("ARC_TRACE_DRAW") && shown < 64) {
    ++shown;
    GLfloat mv[16], pr[16];
    GLint vp[4];
    glGetFloatv(GL_MODELVIEW_MATRIX, mv);
    glGetFloatv(GL_PROJECTION_MATRIX, pr);
    glGetIntegerv(GL_VIEWPORT, vp);
    const short* v = static_cast<const short*>(g_vp);
    std::printf("[draw] %d verts ->", int(A(c, 2)));
    for (int i = 0; i < int(A(c, 2)) && v; ++i) {
      const float x = v[i * 4], y = v[i * 4 + 1];
      const float ex = mv[0] * x + mv[4] * y + mv[12];
      const float ey = mv[1] * x + mv[5] * y + mv[13];
      const float cx = pr[0] * ex + pr[4] * ey + pr[12];
      const float cy = pr[1] * ex + pr[5] * ey + pr[13];
      std::printf(" (%.0f,%.0f)", vp[0] + (cx + 1) * vp[2] / 2,
                  vp[1] + (cy + 1) * vp[3] / 2);
    }
    std::printf("  err=%#x\n", glGetError());
  }
  glDrawArrays(A(c, 0), int(A(c, 1)), int(A(c, 2)));
}


// --- textures --------------------------------------------------------------
void GlGenTextures(Arm32Ctx* c) {
  glGenTextures(int(A(c, 0)), reinterpret_cast<GLuint*>(uintptr_t(A(c, 1))));
}
void GlDeleteTextures(Arm32Ctx* c) {
  glDeleteTextures(int(A(c, 0)),
                   reinterpret_cast<const GLuint*>(uintptr_t(A(c, 1))));
}
void GlBindTexture(Arm32Ctx* c) { glBindTexture(A(c, 0), A(c, 1)); }
void GlTexParameteri(Arm32Ctx* c) {
  glTexParameteri(A(c, 0), A(c, 1), int(A(c, 2)));
}
// ARC_TRACE_TEX=1 says how much of each uploaded texture is not black. A game
// that draws perfect geometry out of empty textures looks exactly like a game
// that draws nothing, and only one of those is a geometry problem.
void GlTexImage2D(Arm32Ctx* c) {
  if (std::getenv("ARC_TRACE_TEX")) {
    const unsigned char* px = static_cast<const unsigned char*>(Ap(c, 8));
    const size_t n = size_t(int(A(c, 3))) * size_t(int(A(c, 4))) * 4;
    size_t lit = 0, alpha = 0;
    for (size_t i = 0; px && i + 3 < n; i += 4) {
      if (px[i] || px[i + 1] || px[i + 2]) ++lit;
      if (px[i + 3]) ++alpha;
    }
    std::printf("[tex] %dx%d fmt=%#x type=%#x data=%p rgb=%zu%% a=%zu%%\n",
                int(A(c, 3)), int(A(c, 4)), A(c, 6), A(c, 7), Ap(c, 8),
                n ? lit * 400 / n : 0, n ? alpha * 400 / n : 0);
  }
  glTexImage2D(A(c, 0), int(A(c, 1)), int(A(c, 2)), int(A(c, 3)), int(A(c, 4)),
               int(A(c, 5)), A(c, 6), A(c, 7), Ap(c, 8));
}

// --- the framebuffer that is not there -------------------------------------
// The guest asks for a framebuffer and a renderbuffer, attaches one to the
// other, and draws. Handing back plausible names and binding zero puts that
// drawing in the window directly.
constexpr uint32_t kFakeName = 1;
constexpr uint32_t kFramebufferCompleteOES = 0x8CD5;
constexpr uint32_t kRenderbufferWidthOES = 0x8D42;
constexpr uint32_t kRenderbufferHeightOES = 0x8D43;

void GenNames(Arm32Ctx* c) {
  const int n = int(A(c, 0));
  GLuint* out = reinterpret_cast<GLuint*>(uintptr_t(A(c, 1)));
  for (int i = 0; i < n && out; ++i) out[i] = kFakeName + GLuint(i);
}

// Nothing to do, and that is the point rather than an omission: no real
// framebuffer object is ever created, so the window's own framebuffer is
// already the target and binding is a no-op. It also keeps this inside GL 1.1
// -- glBindFramebuffer is GL 3.0 and would need a loader.
void BindZero(Arm32Ctx*) {}

void Ignore(Arm32Ctx* c) { ARC_W(c, 0, 0); }

void CheckFramebufferStatus(Arm32Ctx* c) {
  ARC_W(c, 0, kFramebufferCompleteOES);
}

void GetRenderbufferParameteriv(Arm32Ctx* c) {
  // The guest reads these back as its backing width and height and lays every
  // subsequent projection out from them, so they have to be the window's.
  GLint* out = reinterpret_cast<GLint*>(uintptr_t(A(c, 2)));
  if (!out) return;
  const uint32_t pname = A(c, 1);
  if (pname == kRenderbufferWidthOES) *out = WindowWidth();
  else if (pname == kRenderbufferHeightOES) *out = WindowHeight();
  else *out = 0;
}

struct GlShim {
  const char* name;
  ArcCtxFn fn;
};

const GlShim kShims[] = {
    {"_glEnable", GlEnable},
    {"_glDisable", GlDisable},
    {"_glEnableClientState", GlEnableClientState},
    {"_glDisableClientState", GlDisableClientState},
    {"_glBlendFunc", GlBlendFunc},
    {"_glClear", GlClear},
    {"_glClearColor", GlClearColor},
    {"_glViewport", GlViewport},
    {"_glGetIntegerv", GlGetIntegerv},

    {"_glMatrixMode", GlMatrixMode},
    {"_glLoadIdentity", GlLoadIdentity},
    {"_glPushMatrix", GlPushMatrix},
    {"_glPopMatrix", GlPopMatrix},
    {"_glTranslatef", GlTranslatef},
    {"_glScalef", GlScalef},
    {"_glRotatef", GlRotatef},
    {"_glOrthof", GlOrthof},

    {"_glVertexPointer", GlVertexPointer},
    {"_glTexCoordPointer", GlTexCoordPointer},
    {"_glColorPointer", GlColorPointer},
    {"_glDrawArrays", GlDrawArrays},

    {"_glGenTextures", GlGenTextures},
    {"_glDeleteTextures", GlDeleteTextures},
    {"_glBindTexture", GlBindTexture},
    {"_glTexParameteri", GlTexParameteri},
    {"_glTexImage2D", GlTexImage2D},

    {"_glGenFramebuffersOES", GenNames},
    {"_glGenRenderbuffersOES", GenNames},
    {"_glBindFramebufferOES", BindZero},
    {"_glBindRenderbufferOES", Ignore},
    {"_glFramebufferRenderbufferOES", Ignore},
    {"_glDeleteFramebuffersOES", Ignore},
    {"_glDeleteRenderbuffersOES", Ignore},
    {"_glCheckFramebufferStatusOES", CheckFramebufferStatus},
    {"_glGetRenderbufferParameterivOES", GetRenderbufferParameteriv},
};

#endif  // ARC_HAVE_SDL2

}  // namespace

size_t InstallGlShims(const MachOImage& img) {
#if defined(ARC_HAVE_SDL2)
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const auto& s : kShims)
      if (im.name == s.name) {
        arc_register_ctx_native(im.stub, s.name, s.fn);
        ++claimed;
      }
  }
  return claimed;
#else
  (void)img;
  return 0;
#endif
}

}  // namespace arc
