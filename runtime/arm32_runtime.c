// Runtime support for lifted code that cannot be expressed inline.
//
// `arc_dispatch` lives here but the *table* does not: only the generated
// module knows address -> function, so it installs its own through
// `arc_set_dispatch`. The layering rule is that anything the shim calls must
// be defined in the library, and anything generated must plug in -- the shim
// itself has to dispatch, because a guest entry point is a guest address.
// That rule has been learned twice from opposite directions, so it is written
// down here rather than rediscovered.

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
/* Deep enough to hold the origin of a repeating cycle. At 256, a run that
   throws in a loop wraps the ring in about thirty iterations and the frame
   that started it is gone -- which is precisely the frame the report exists
   to name. Two words each, so 8192 is 64 KB and buys the whole answer. */
#define ARC_FRAME_RING 8192
static uint32_t t_frames[ARC_FRAME_RING];
static uint32_t t_callers[ARC_FRAME_RING];
static size_t t_frame_next, t_frame_seen;

// The header turns this into a no-op macro when ARC_FRAMES is off, which would
// otherwise eat the definition below.
#undef arc_frame_note

// Defined unconditionally, even though the header hides it behind ARC_FRAMES.
// The flag belongs to whoever is *generating* calls, and that is a different
// target from this one -- gating the definition on it means a lifted program
// built with frames cannot link against a library built without, which is
// exactly the configuration anyone would try first.
static Arm32Ctx* g_current_ctx;

void arc_set_current_context(Arm32Ctx* c) { g_current_ctx = c; }
Arm32Ctx* arc_current_context(void) { return g_current_ctx; }

static long g_frame_budget = 0;
static long g_frame_budget_start = 0;

void arc_frame_budget(long entries) {
  g_frame_budget = entries;
  g_frame_budget_start = entries;
}

void arc_frame_budget_reset(void) { g_frame_budget = g_frame_budget_start; }

void arc_frame_note(uint32_t packed) {
  t_frames[t_frame_next] = packed;
  /* lr still holds the return address here: the note is emitted at the top of
     the function, before the prologue pushes it. */
  t_callers[t_frame_next] =
      g_current_ctx ? g_current_ctx->r[14] : 0;
  t_frame_next = (t_frame_next + 1) % ARC_FRAME_RING;
  ++t_frame_seen;
  if (g_frame_budget && --g_frame_budget <= 0) {
    g_frame_budget = 0;
    arc_trap(0, "the guest entered its function budget without reaching the "
                "frame loop; it is going round somewhere below");
  }
}

size_t arc_frame_count(void) {
  return t_frame_seen < ARC_FRAME_RING ? t_frame_seen : ARC_FRAME_RING;
}

uint32_t arc_frame_at(size_t back) {
  if (back >= arc_frame_count()) return 0;
  return t_frames[(t_frame_next + ARC_FRAME_RING - 1 - back) % ARC_FRAME_RING];
}

uint32_t arc_frame_caller(size_t back) {
  if (back >= arc_frame_count()) return 0;
  return t_callers[(t_frame_next + ARC_FRAME_RING - 1 - back) % ARC_FRAME_RING];
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

// Sized for a whole framework surface, not a handful of special cases. The
// first version held 64 and filled up silently: the GL shims alone are 35, and
// once the table was full `objc_msgSend` registered as a no-op and the guest
// reported it as unimplemented -- with every one of its own classes still
// loading correctly, so the symptom pointed nowhere near the cause. A limit
// that is reached quietly is worse than one that is too small.
#define ARC_MAX_CTX_NATIVES 1024
static CtxNative g_ctx_natives[ARC_MAX_CTX_NATIVES];
static size_t g_ctx_native_count;

void arc_register_ctx_native(uint32_t address, const char* name, ArcCtxFn fn) {
  if (g_ctx_native_count >= ARC_MAX_CTX_NATIVES) {
    fprintf(stderr,
            "arc: the context-native table is full at %d; '%s' and "
            "everything after it is unreachable\n",
            ARC_MAX_CTX_NATIVES, name ? name : "?");
    return;
  }
  if (!address) return;
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

// Imports that exist and have no implementation yet. Kept apart from the
// natives so a miss can say which of the two kinds it is: a named import with
// nothing behind it is simply work, whereas an address matching nothing at all
// is a hole in the lift, and those want telling apart at a glance.
typedef struct {
  uint32_t address;
  const char* name;
  const char* owner;
} StubEntry;

#define ARC_MAX_STUBS 1024
static StubEntry g_stubs[ARC_MAX_STUBS];
static size_t g_stub_count;

const char* arc_native_name(uint32_t address) {
  for (size_t i = 0; i < g_native_count; ++i)
    if (g_natives[i].address == address) return g_natives[i].name;
  for (size_t i = 0; i < g_ctx_native_count; ++i)
    if (g_ctx_natives[i].address == address) return g_ctx_natives[i].name;
  return NULL;
}

void arc_register_stub(uint32_t address, const char* name, const char* owner) {
  if (!address || g_stub_count >= ARC_MAX_STUBS) return;
  for (size_t i = 0; i < g_stub_count; ++i)
    if (g_stubs[i].address == address) return;
  g_stubs[g_stub_count].address = address;
  g_stubs[g_stub_count].name = name;
  g_stubs[g_stub_count].owner = owner;
  ++g_stub_count;
}

static int g_permissive;
// Which named imports were answered with zero, in the order first seen. The
// names are the ones registered with the stub, so they stay alive.
#define ARC_MAX_MISSING 512
static const char* g_missing[ARC_MAX_MISSING];
static size_t g_missing_count;

void arc_set_permissive(int on) { g_permissive = on; }
size_t arc_missing_count(void) { return g_missing_count; }
const char* arc_missing_at(size_t i) {
  return i < g_missing_count ? g_missing[i] : 0;
}

static void arc_note_missing(const char* name) {
  for (size_t i = 0; i < g_missing_count; ++i)
    if (g_missing[i] == name) return;
  if (g_missing_count < ARC_MAX_MISSING) g_missing[g_missing_count++] = name;
}

static ArcDispatchFn g_dispatch;

void arc_set_dispatch(ArcDispatchFn fn) { g_dispatch = fn; }

void arc_dispatch(Arm32Ctx* c, uint32_t target) {
  if (g_dispatch) {
    g_dispatch(c, target);
    return;
  }
  arc_dispatch_miss(c, target);
}

/* ARC_TRACE_CALLS=<substring>, or "*" for everything: a shell cannot easily
   pass an empty value. A name in the trail says the guest called memmove; the
   arguments say whether it asked for a sane length. This is what located an
   allocation of eighteen exabytes on the other project, after five rounds of
   inference had not. */
static int arc_trace_call_filter(const char* name) {
  static const char* filter;
  static int checked;
  if (!checked) { filter = getenv("ARC_TRACE_CALLS"); checked = 1; }
  return filter && name &&
         (!*filter || filter[0] == '*' || strstr(name, filter) != NULL);
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
    /* The same argument trace the plain natives get. Most of the GL surface is
       registered this way, and "it called glDrawArrays" says nothing that "it
       called glDrawArrays with a count of zero" does not say better. */
    if (arc_trace_call_filter(g_ctx_natives[i].name))
      fprintf(stderr, "[call] %-26s r0=%#x r1=%#x r2=%#x r3=%#x\n",
              g_ctx_natives[i].name, c->r[0], c->r[1], c->r[2], c->r[3]);
    g_ctx_natives[i].fn(c);
    return;
  }
  for (size_t i = 0; i < g_native_count; ++i) {
    if (g_natives[i].address != addr) continue;
    arc_trace_note(g_natives[i].name);
    if (arc_trace_call_filter(g_natives[i].name))
      fprintf(stderr, "[call] %-26s r0=%#x r1=%#x r2=%#x r3=%#x\n",
              g_natives[i].name, c->r[0], c->r[1], c->r[2], c->r[3]);
    const uint32_t* stack = (const uint32_t*)(uintptr_t)ARC_SP(c);
    c->r[0] = g_natives[i].fn(c->r[0], c->r[1], c->r[2], c->r[3],
                              stack[0], stack[1], stack[2], stack[3]);
    return;
  }
  char msg[192];
  for (size_t i = 0; i < g_stub_count; ++i) {
    if (g_stubs[i].address != addr) continue;
    arc_trace_note(g_stubs[i].name);
    if (g_permissive) {
      /* Zero, and written down. Most of these return a status the caller
         checks or a pointer it tests, so zero carries a surprising distance --
         and where it does not, that is worth learning in the same run. */
      arc_note_missing(g_stubs[i].name);
      c->r[0] = 0;
      return;
    }
    snprintf(msg, sizeof(msg), "%s is not implemented -- %s owes it",
             g_stubs[i].name, g_stubs[i].owner);
    arc_trap(c, msg);
    return;
  }
  snprintf(msg, sizeof(msg),
           "indirect branch to %#x, neither lifted nor a known import", target);
  arc_trap(c, msg);
}

// The fallback for a host with no lifted program is above, in arc_dispatch
// itself: with nothing installed it goes straight to arc_dispatch_miss, which
// resolves the branch against the registered natives or traps loudly. That is
// the right behaviour for triage and for bringing the shim up, and it needs no
// compile-time flag to select it.
