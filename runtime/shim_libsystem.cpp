// The C library the guest expects, answered by the host's.
//
// This is the cheapest part of the whole shim surface and the one place the
// import list flatters the work: Canabalt names exactly ten libSystem symbols
// and three from libgcc. Most map straight onto the host's own C runtime.
//
// Two things stop it being a pure forwarding table.
//
// Anything returning a pointer must return a *guest* pointer -- see arc_mem.h.
// Forwarding malloc to the host's malloc compiles, links, runs, and hands the
// guest the bottom half of a 64-bit address.
//
// And the floating-point calls do not take their arguments where C would put
// them. iOS on armv6 passes floats and doubles in the integer registers at a
// public boundary, so `sin` arrives as a double split across r0 and r1 rather
// than in a VFP register. Those get the fuller shim that sees the context.
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "arc_mem.h"
#include "arm32_context.h"
#include "macho_image.h"

namespace arc {
namespace {

uint32_t ShimMalloc(uint32_t size, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  return arc_guest_alloc(size, 16);
}

uint32_t ShimCalloc(uint32_t count, uint32_t size, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  return arc_guest_calloc(count, size);
}

uint32_t ShimFree(uint32_t p, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                  uint32_t, uint32_t) {
  arc_guest_free(p);
  return 0;
}

uint32_t ShimArc4Random(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                        uint32_t, uint32_t, uint32_t) {
  // Not the real arc4random, and it does not need to be: nothing here is a
  // security boundary and a game wants variety, not entropy.
  static uint32_t state = 0x2545F491u;
  state ^= state << 13;
  state ^= state >> 17;
  state ^= state << 5;
  return state;
}

int g_exit_code = 0;
bool g_exited = false;

// The guest exiting is a result, not a reason to end the process. Calling
// std::exit here would take the report down with it -- the trail, the heap
// figure, the list of messages nobody answered -- which is exactly what a run
// is for. So it unwinds to the recovery point instead, and Boot decides what
// to say about it.
uint32_t ShimExit(uint32_t code, uint32_t, uint32_t, uint32_t, uint32_t,
                  uint32_t, uint32_t, uint32_t) {
  g_exit_code = int(code);
  g_exited = true;
  arc_trap(nullptr, "the guest called exit");
  return 0;
}

// --- the ones whose arguments are not where C would put them ---------------

float F32(uint32_t bits) {
  float f;
  std::memcpy(&f, &bits, 4);
  return f;
}

uint32_t Bits(float f) {
  uint32_t u;
  std::memcpy(&u, &f, 4);
  return u;
}

double F64(uint32_t lo, uint32_t hi) {
  const uint64_t u = uint64_t(lo) | (uint64_t(hi) << 32);
  double d;
  std::memcpy(&d, &u, 8);
  return d;
}

void SetF64(Arm32Ctx* c, double d) {
  uint64_t u;
  std::memcpy(&u, &d, 8);
  ARC_W(c, 0, uint32_t(u));
  ARC_W(c, 1, uint32_t(u >> 32));
}

void ShimCeilf(Arm32Ctx* c) { ARC_W(c, 0, Bits(std::ceil(F32(ARC_R(c, 0))))); }
void ShimFloorf(Arm32Ctx* c) { ARC_W(c, 0, Bits(std::floor(F32(ARC_R(c, 0))))); }
void ShimSin(Arm32Ctx* c) { SetF64(c, std::sin(F64(ARC_R(c, 0), ARC_R(c, 1)))); }
void ShimCos(Arm32Ctx* c) { SetF64(c, std::cos(F64(ARC_R(c, 0), ARC_R(c, 1)))); }

// --- libgcc ----------------------------------------------------------------
// armv6 has no divide instruction, so the compiler calls these. Signed
// division by zero and INT_MIN / -1 are undefined in C, and the guest is
// entitled to do either, so both are answered the way the runtime does rather
// than by letting the host trap.

void ShimDivsi3(Arm32Ctx* c) {
  const int32_t a = int32_t(ARC_R(c, 0)), b = int32_t(ARC_R(c, 1));
  if (b == 0) ARC_W(c, 0, 0);
  else if (a == INT32_MIN && b == -1) ARC_W(c, 0, uint32_t(INT32_MIN));
  else ARC_W(c, 0, uint32_t(a / b));
}

void ShimModsi3(Arm32Ctx* c) {
  const int32_t a = int32_t(ARC_R(c, 0)), b = int32_t(ARC_R(c, 1));
  if (b == 0) ARC_W(c, 0, 0);
  else if (a == INT32_MIN && b == -1) ARC_W(c, 0, 0);
  else ARC_W(c, 0, uint32_t(a % b));
}

void ShimUmodsi3(Arm32Ctx* c) {
  const uint32_t a = ARC_R(c, 0), b = ARC_R(c, 1);
  ARC_W(c, 0, b ? a % b : 0);
}

struct PlainShim {
  const char* name;
  ArcNativeFn fn;
};

struct CtxShim {
  const char* name;
  ArcCtxFn fn;
};

const PlainShim kPlain[] = {
    {"_malloc", ShimMalloc},
    {"_calloc", ShimCalloc},
    {"_free", ShimFree},
    {"_arc4random", ShimArc4Random},
    {"_exit", ShimExit},
};

const CtxShim kCtx[] = {
    {"_ceilf", ShimCeilf},   {"_floorf", ShimFloorf},
    {"_sin", ShimSin},       {"_cos", ShimCos},
    {"___divsi3", ShimDivsi3}, {"___modsi3", ShimModsi3},
    {"___umodsi3", ShimUmodsi3},
};

}  // namespace

bool GuestExited(int* code) {
  if (code) *code = g_exit_code;
  return g_exited;
}

// Registers everything this file answers, at the stub address the guest
// branches to. Returns how many imports it claimed.
size_t InstallLibSystemShims(const MachOImage& img) {
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const auto& s : kPlain)
      if (im.name == s.name) {
        arc_register_native(im.stub, s.name, s.fn);
        ++claimed;
      }
    for (const auto& s : kCtx)
      if (im.name == s.name) {
        arc_register_ctx_native(im.stub, s.name, s.fn);
        ++claimed;
      }
  }
  return claimed;
}

}  // namespace arc
