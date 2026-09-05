// Runtime support for lifted code that cannot be expressed inline.
//
// `arc_dispatch` lives here but the *table* does not: only the generated
// module knows address -> function, so it installs its own through
// `arc_set_dispatch`. The layering rule is that anything the shim calls must
// be defined in the library, and anything generated must plug in -- the shim
// itself has to dispatch, because a guest entry point is a guest address.
// androidrecomp learned this twice from opposite directions; inherited here
// rather than rediscovered.

#include "arm32_context.h"

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#define ARC_THREAD_LOCAL __declspec(thread)
#else
#define ARC_THREAD_LOCAL __thread
#endif

// --- traps -----------------------------------------------------------------

static ARC_THREAD_LOCAL jmp_buf* t_recovery;
static ARC_THREAD_LOCAL char t_last_trap[256];

void arc_set_recovery(void* jmp_buffer) { t_recovery = (jmp_buf*)jmp_buffer; }

const char* arc_last_trap(void) { return t_last_trap; }

void arc_trap(Arm32Ctx* c, const char* what) {
  (void)c;
  snprintf(t_last_trap, sizeof(t_last_trap), "%s", what ? what : "?");
  if (t_recovery) longjmp(*t_recovery, 1);
  fprintf(stderr, "guest trap: %s\n", t_last_trap);
  abort();
}

// --- what the guest was doing ----------------------------------------------
// A fault in lifted code names an address in the data it touched and never the
// code that touched it, and the host call stack is tens of thousands of
// identically shaped C functions. These two rings are what make a fault
// self-describing. Both are rings rather than stacks: nothing to pop, so no
// return path can be missed.

#define ARC_TRACE 64
static ARC_THREAD_LOCAL const char* t_trace[ARC_TRACE];
static ARC_THREAD_LOCAL size_t t_trace_next, t_trace_seen;

void arc_trace_note(const char* what) {
  t_trace[t_trace_next] = what;
  t_trace_next = (t_trace_next + 1) % ARC_TRACE;
  ++t_trace_seen;
}

size_t arc_trace_count(void) {
  return t_trace_seen < ARC_TRACE ? t_trace_seen : ARC_TRACE;
}

const char* arc_trace_at(size_t back) {
  if (back >= arc_trace_count()) return 0;
  return t_trace[(t_trace_next + ARC_TRACE - 1 - back) % ARC_TRACE];
}

void arc_trace_clear(void) { t_trace_next = t_trace_seen = 0; }

// Global rather than per-thread, deliberately. A per-thread ring can only be
// read from the thread that filled it, which forces reporting to happen inside
// the guest call itself -- exactly where it is least safe to do anything.
#define ARC_FRAME_RING 256
static uint32_t t_frames[ARC_FRAME_RING];
static size_t t_frame_next, t_frame_seen;

#if defined(ARC_FRAMES)
void arc_frame_note(uint32_t packed) {
  t_frames[t_frame_next] = packed;
  t_frame_next = (t_frame_next + 1) % ARC_FRAME_RING;
  ++t_frame_seen;
}
#endif

size_t arc_frame_count(void) {
  return t_frame_seen < ARC_FRAME_RING ? t_frame_seen : ARC_FRAME_RING;
}

uint32_t arc_frame_at(size_t back) {
  if (back >= arc_frame_count()) return 0;
  return t_frames[(t_frame_next + ARC_FRAME_RING - 1 - back) % ARC_FRAME_RING];
}

void arc_frame_clear(void) { t_frame_next = t_frame_seen = 0; }

// --- native call bridge ----------------------------------------------------

typedef struct {
  uint32_t address;
  const char* name;
  ArcNativeFn fn;
} NativeEntry;

// ponytail: a linear array, searched only on a dispatch miss -- once per call
// *out* of the guest. Sort it and bisect if a profile ever says otherwise.
#define ARC_MAX_NATIVES 2048
static NativeEntry g_natives[ARC_MAX_NATIVES];
static size_t g_native_count;

typedef struct { uint32_t address; const char* name; ArcCtxFn fn; } CtxNative;

#define ARC_MAX_CTX_NATIVES 64
static CtxNative g_ctx_natives[ARC_MAX_CTX_NATIVES];
static size_t g_ctx_native_count;

void arc_register_ctx_native(uint32_t address, const char* name, ArcCtxFn fn) {
  if (!address || g_ctx_native_count >= ARC_MAX_CTX_NATIVES) return;
  for (size_t i = 0; i < g_ctx_native_count; ++i)
    if (g_ctx_natives[i].address == address) return;
  g_ctx_natives[g_ctx_native_count].address = address;
  g_ctx_natives[g_ctx_native_count].name = name;
  g_ctx_natives[g_ctx_native_count].fn = fn;
  ++g_ctx_native_count;
}

void arc_register_native(uint32_t address, const char* name, ArcNativeFn fn) {
  if (!address || !fn || g_native_count >= ARC_MAX_NATIVES) return;
  for (size_t i = 0; i < g_native_count; ++i)
    if (g_natives[i].address == address) return;
  g_natives[g_native_count].address = address;
  g_natives[g_native_count].name = name;
  g_natives[g_native_count].fn = fn;
  ++g_native_count;
}

// ponytail: AAPCS puts the first four integer arguments in r0-r3 and the rest
// on the stack, so this reads four more words off the guest's own stack and
// passes eight. That covers allocation, string, file and threading calls --
// nearly everything a guest asks the host for. It does NOT carry
// floating-point arguments (VFP, or r0-r3 again under the soft-float ABI these
// binaries were built with), and it does not carry a returned double in
// r0:r1. Register those through arc_register_ctx_native, which sees the whole
// context, rather than widening this.

static ArcDispatchFn g_dispatch;

void arc_set_dispatch(ArcDispatchFn fn) { g_dispatch = fn; }

void arc_dispatch(Arm32Ctx* c, uint32_t target) {
  if (g_dispatch) {
    g_dispatch(c, target);
    return;
  }
  arc_dispatch_miss(c, target);
}

void arc_dispatch_miss(Arm32Ctx* c, uint32_t target) {
  // The Thumb bit is not part of any address; strip it before comparing, or a
  // native reached through `blx` never matches the one that was registered.
  const uint32_t addr = ARC_CODE_ADDR(target);
  // Context-taking natives first: they are a strict superset of what the plain
  // thunk can express, so a name registered both ways wants this one.
  for (size_t i = 0; i < g_ctx_native_count; ++i) {
    if (g_ctx_natives[i].address != addr) continue;
    arc_trace_note(g_ctx_natives[i].name);
    g_ctx_natives[i].fn(c);
    return;
  }
  for (size_t i = 0; i < g_native_count; ++i) {
    if (g_natives[i].address != addr) continue;
    arc_trace_note(g_natives[i].name);
    // Optional argument trace. A name in the trail says the guest called
    // memmove; the arguments say whether it asked for a sane length. This is
    // what located an allocation of eighteen exabytes on the other project,
    // after five rounds of inference had not.
    {
      static const char* filter;
      static int checked;
      if (!checked) { filter = getenv("ARC_TRACE_CALLS"); checked = 1; }
      // "*" matches everything: a shell cannot easily pass an empty value.
      if (filter && (!*filter || filter[0] == '*' ||
                     strstr(g_natives[i].name, filter)))
        fprintf(stderr, "[call] %-12s r0=%#x r1=%#x r2=%#x r3=%#x\n",
                g_natives[i].name, c->r[0], c->r[1], c->r[2], c->r[3]);
    }
    const uint32_t* stack = (const uint32_t*)(uintptr_t)ARC_SP(c);
    c->r[0] = g_natives[i].fn(c->r[0], c->r[1], c->r[2], c->r[3],
                              stack[0], stack[1], stack[2], stack[3]);
    return;
  }
  char msg[128];
  snprintf(msg, sizeof(msg),
           "indirect branch to %#x, neither lifted nor a known import", target);
  arc_trap(c, msg);
}

// The fallback for a host with no lifted program is above, in arc_dispatch
// itself: with nothing installed it goes straight to arc_dispatch_miss, which
// resolves the branch against the registered natives or traps loudly. That is
// the right behaviour for triage and for bringing the shim up, and it needs no
// compile-time flag to select it.
