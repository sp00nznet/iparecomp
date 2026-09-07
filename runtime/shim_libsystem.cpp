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
#include <ctime>
#include <strings.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>

#include "arc_mem.h"
#include "arm32_context.h"
#include "macho_image.h"

namespace arc {

// Defined in shim_objects.cpp: where --bundle pointed. A guest asking for a
// relative path means one relative to its own bundle.
std::string BundlePath();

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


// --- the C library proper ---------------------------------------------------
//
// Angry Birds Rio names 127 libSystem symbols where Canabalt named ten, and
// almost all of the difference is plain C: memcpy, strlen, the math
// functions. They are nearly free here for a reason worth stating, because it
// is the whole payoff of the zero-slide design: **a guest pointer is a host
// pointer**. The image is mapped at its own link address and the guest heap is
// real host memory below 4 GB, so `strlen(p)` can be handed the guest's own
// `p` and be right. Nothing is copied and nothing is translated.
//
// What still needs care is the other direction. Anything that *returns* a
// pointer of its own -- malloc, realloc -- must return something below 4 GB,
// and the host's allocator will not. Anything returning a pointer *into* its
// own argument is safe, because that pointer was already the guest's.

char* Ptr(uint32_t a) { return reinterpret_cast<char*>(uintptr_t(a)); }
const char* CPtr(uint32_t a) {
  return reinterpret_cast<const char*>(uintptr_t(a));
}
uint32_t Back(const void* p) { return uint32_t(uintptr_t(p)); }

#define ARC_LIBC(fn, expr)                                                     \
  uint32_t fn(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t,        \
              uint32_t, uint32_t, uint32_t) {                                  \
    (void)a; (void)b; (void)c; (void)d;                                        \
    return (expr);                                                             \
  }

// The block moves get a guard the rest do not, because they are where a bad
// guest pointer becomes a *host* crash. memcpy to a null or nonsense address
// segfaults the process, and an access violation reports nothing: no trail,
// no heap figure, no name. Asking first turns the same bug into a sentence.
// It costs one range check per call against work that is already O(n).
// `plausible` and not `owns`: the heap and the stack are not the whole of what
// a guest may legitimately write. A global lives in __DATA -- including the
// zero-filled BSS past the end of the file -- and copying into one is ordinary.
// Checking both ends catches a length that runs off the end of a real object
// as well as a pointer that was never one.
bool Reachable(uint32_t p, uint32_t n) {
  return p && arc_guest_plausible(p) && arc_guest_plausible(p + n - 1);
}

bool Movable(const char* who, uint32_t dst, uint32_t src, uint32_t n) {
  if (!n) return false;
  if (Reachable(dst, n) && Reachable(src, n)) return true;
  char why[160];
  std::snprintf(why, sizeof why,
                "%s(%#x, %#x, %u): %s is not memory the guest can reach", who,
                dst, src, n, Reachable(dst, n) ? "the source" : "the destination");
  arc_trap(nullptr, why);
  return false;
}

uint32_t ShimMemcpy(uint32_t a, uint32_t b, uint32_t c, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  if (Movable("memcpy", a, b, c)) std::memcpy(Ptr(a), CPtr(b), c);
  return a;
}

uint32_t ShimMemmove(uint32_t a, uint32_t b, uint32_t c, uint32_t, uint32_t,
                     uint32_t, uint32_t, uint32_t) {
  if (Movable("memmove", a, b, c)) std::memmove(Ptr(a), CPtr(b), c);
  return a;
}

uint32_t ShimMemset(uint32_t a, uint32_t b, uint32_t c, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  if (!c) return a;
  if (Reachable(a, c)) {
    std::memset(Ptr(a), int(b), c);
    return a;
  }
  char why[128];
  std::snprintf(why, sizeof why,
                "memset(%#x, %u, %u): not memory the guest can reach", a, b, c);
  arc_trap(nullptr, why);
  return a;
}
ARC_LIBC(ShimMemcmp, uint32_t(int32_t(std::memcmp(CPtr(a), CPtr(b), c))))
ARC_LIBC(ShimMemchr, Back(std::memchr(CPtr(a), int(b), c)))
ARC_LIBC(ShimStrlen, uint32_t(std::strlen(CPtr(a))))
ARC_LIBC(ShimStrcmp, uint32_t(int32_t(std::strcmp(CPtr(a), CPtr(b)))))
ARC_LIBC(ShimStrncmp, uint32_t(int32_t(std::strncmp(CPtr(a), CPtr(b), c))))
ARC_LIBC(ShimStrcoll, uint32_t(int32_t(std::strcoll(CPtr(a), CPtr(b)))))
ARC_LIBC(ShimStrcpy, (std::strcpy(Ptr(a), CPtr(b)), a))
ARC_LIBC(ShimStrncpy, (std::strncpy(Ptr(a), CPtr(b), c), a))
ARC_LIBC(ShimStrcat, (std::strcat(Ptr(a), CPtr(b)), a))
ARC_LIBC(ShimStrncat, (std::strncat(Ptr(a), CPtr(b), c), a))
ARC_LIBC(ShimStrchr, Back(std::strchr(CPtr(a), int(b))))
ARC_LIBC(ShimStrrchr, Back(std::strrchr(CPtr(a), int(b))))
ARC_LIBC(ShimStrstr, Back(std::strstr(CPtr(a), CPtr(b))))
ARC_LIBC(ShimStrpbrk, Back(std::strpbrk(CPtr(a), CPtr(b))))
ARC_LIBC(ShimStrcspn, uint32_t(std::strcspn(CPtr(a), CPtr(b))))
ARC_LIBC(ShimStrcasecmp, uint32_t(int32_t(strcasecmp(CPtr(a), CPtr(b)))))
ARC_LIBC(ShimStrtok, Back(std::strtok(a ? Ptr(a) : nullptr, CPtr(b))))
ARC_LIBC(ShimStrerror, Back(std::strerror(int(a))))
ARC_LIBC(ShimAbort, (arc_trap(nullptr, "the guest called abort"), 0u))
ARC_LIBC(ShimRand, uint32_t(std::rand()))
ARC_LIBC(ShimSrand, (std::srand(a), 0u))
ARC_LIBC(ShimNop, 0u)
ARC_LIBC(ShimTime, uint32_t(std::time(nullptr)))
ARC_LIBC(ShimClock, uint32_t(std::clock()))
ARC_LIBC(ShimSystem, 0xFFFFFFFFu)

uint32_t ShimStrtol(uint32_t str, uint32_t end, uint32_t base, uint32_t,
                    uint32_t, uint32_t, uint32_t, uint32_t) {
  char** e = end ? reinterpret_cast<char**>(uintptr_t(end)) : nullptr;
  return uint32_t(std::strtol(CPtr(str), e, int(base)));
}

uint32_t ShimStrtoul(uint32_t str, uint32_t end, uint32_t base, uint32_t,
                     uint32_t, uint32_t, uint32_t, uint32_t) {
  char** e = end ? reinterpret_cast<char**>(uintptr_t(end)) : nullptr;
  return uint32_t(std::strtoul(CPtr(str), e, int(base)));
}

// realloc has to stay inside the guest heap, so it is a fresh block and a
// copy rather than a forward. The old size is not knowable from here, so the
// copy is bounded by the new one: right for a growth, and for a shrink it
// copies only what survives.
uint32_t ShimRealloc(uint32_t p, uint32_t size, uint32_t, uint32_t, uint32_t,
                     uint32_t, uint32_t, uint32_t) {
  if (!size) {
    arc_guest_free(p);
    return 0;
  }
  const uint32_t fresh = arc_guest_alloc(size, 16);
  if (!fresh) return 0;
  if (p) {
    std::memcpy(Ptr(fresh), CPtr(p), size);
    arc_guest_free(p);
  }
  return fresh;
}

uint32_t ShimGettimeofday(uint32_t tv, uint32_t, uint32_t, uint32_t, uint32_t,
                          uint32_t, uint32_t, uint32_t) {
  if (tv) {
    const uint64_t us =
        uint64_t(std::clock()) * 1000000ull / uint64_t(CLOCKS_PER_SEC);
    ARC_ST32(tv, uint32_t(us / 1000000ull));
    ARC_ST32(tv + 4, uint32_t(us % 1000000ull));
  }
  return 0;
}

// --- the float ones, whose arguments are in the integer registers ----------

#define ARC_LIBCF(fn, expr)                                                    \
  void fn(Arm32Ctx* c) {                                                       \
    const float x = F32(ARC_R(c, 0));                                          \
    const float y = F32(ARC_R(c, 1));                                          \
    (void)x; (void)y;                                                          \
    ARC_W(c, 0, Bits(expr));                                                   \
  }

ARC_LIBCF(ShimSinf, std::sin(x))
ARC_LIBCF(ShimCosf, std::cos(x))
ARC_LIBCF(ShimTanf, std::tan(x))
ARC_LIBCF(ShimAsinf, std::asin(x))
ARC_LIBCF(ShimAcosf, std::acos(x))
ARC_LIBCF(ShimAtanf, std::atan(x))
ARC_LIBCF(ShimAtan2f, std::atan2(x, y))
ARC_LIBCF(ShimSinhf, std::sinh(x))
ARC_LIBCF(ShimCoshf, std::cosh(x))
ARC_LIBCF(ShimTanhf, std::tanh(x))
ARC_LIBCF(ShimExpf, std::exp(x))
ARC_LIBCF(ShimLogf, std::log(x))
ARC_LIBCF(ShimLog10f, std::log10(x))
ARC_LIBCF(ShimPowf, std::pow(x, y))
ARC_LIBCF(ShimFmodf, std::fmod(x, y))

void ShimLdexpf(Arm32Ctx* c) {
  ARC_W(c, 0, Bits(std::ldexp(F32(ARC_R(c, 0)), int32_t(ARC_R(c, 1)))));
}

#define ARC_LIBCD(fn, expr)                                                    \
  void fn(Arm32Ctx* c) {                                                       \
    const double x = F64(ARC_R(c, 0), ARC_R(c, 1));                            \
    const double y = F64(ARC_R(c, 2), ARC_R(c, 3));                            \
    (void)x; (void)y;                                                          \
    SetF64(c, expr);                                                           \
  }

ARC_LIBCD(ShimPow, std::pow(x, y))
ARC_LIBCD(ShimFmod, std::fmod(x, y))
ARC_LIBCD(ShimTan, std::tan(x))


// --- C++, Objective-C and the unwinder -------------------------------------
//
// Angry Birds is a C++ game with an Objective-C shell, which Canabalt was not,
// so it names a surface Canabalt never touched: operator new, the Itanium
// exception ABI, and the SjLj unwinder armv6 uses instead of DWARF.
//
// operator new is malloc's problem again and for the same reason -- a host
// allocation is above 4 GB and the guest cannot hold it.

uint32_t ShimNew(uint32_t size, uint32_t, uint32_t, uint32_t, uint32_t,
                 uint32_t, uint32_t, uint32_t) {
  // A throwing new that cannot throw. Returning zero is what the nothrow form
  // does and is far better than pretending: the guest checks it, and the
  // alternative is an exception this cannot raise.
  return arc_guest_alloc(size ? size : 1, 16);
}

uint32_t ShimDelete(uint32_t p, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  arc_guest_free(p);
  return 0;
}

// errno, as a pointer to an int the guest can read and write. One cell for
// the whole guest, which is right while it is single-threaded and is the
// thing to revisit when it is not.
uint32_t ShimErrno(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t) {
  static uint32_t cell = 0;
  if (!cell) cell = arc_guest_calloc(1, 4);
  return cell;
}

// SjLj exception registration. armv6 has no unwind tables, so a function with
// cleanups pushes a context on entry and pops it on exit, and the whole
// mechanism is inert unless something actually throws. Nothing here does, so
// the push and the pop cost nothing -- but a *throw* must not be answered
// quietly, because unwinding to the wrong place is worse than stopping.
uint32_t ShimUnwindNop(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                       uint32_t, uint32_t, uint32_t) {
  return 0;
}

uint32_t ShimThrow(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t) {
  arc_trap(nullptr,
           "the guest threw a C++ exception; SjLj unwinding is not implemented");
  return 0;
}


// --- stdio ------------------------------------------------------------------
//
// Canabalt read its assets through NSBundle; Angry Birds reads them through
// fopen, so this is a surface the first port never needed. The whole of it is
// a handle table and a path fixup.
//
// A `FILE*` cannot be forwarded. The host's is above 4 GB and the guest holds
// it in 32 bits, so every open gets a four-byte guest allocation whose address
// is the token the guest keeps -- unique, non-null, and comfortably a pointer
// as far as the guest is concerned.
//
// The path needs help too. A guest asks for what it saw on a device, so a
// bare relative path is relative to the *bundle*, not to wherever the host
// happens to have been started.

std::map<uint32_t, FILE*>& OpenFiles() {
  static std::map<uint32_t, FILE*> m;
  return m;
}

FILE* HostFile(uint32_t token) {
  auto it = OpenFiles().find(token);
  return it == OpenFiles().end() ? nullptr : it->second;
}

uint32_t ShimFopen(uint32_t path, uint32_t mode, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t, uint32_t) {
  if (!path) return 0;
  const std::string want = CPtr(path);
  const std::string how = mode ? CPtr(mode) : "rb";
  FILE* f = std::fopen(want.c_str(), how.c_str());
  if (!f && !want.empty() && want[0] != '/') {
    const std::string in_bundle = BundlePath() + "/" + want;
    f = std::fopen(in_bundle.c_str(), how.c_str());
  }
  if (std::getenv("ARC_TRACE_FILE"))
    std::printf("[file] fopen(\"%s\", \"%s\") -> %s\n", want.c_str(),
                how.c_str(), f ? "ok" : "no such file");
  if (!f) return 0;
  const uint32_t token = arc_guest_alloc(4, 4);
  if (!token) {
    std::fclose(f);
    return 0;
  }
  OpenFiles()[token] = f;
  return token;
}

uint32_t ShimFclose(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (!f) return 0xFFFFFFFFu;
  std::fclose(f);
  OpenFiles().erase(token);
  arc_guest_free(token);
  return 0;
}

uint32_t ShimFread(uint32_t ptr, uint32_t size, uint32_t n, uint32_t token,
                   uint32_t, uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (!f || !ptr) return 0;
  return uint32_t(std::fread(Ptr(ptr), size, n, f));
}

uint32_t ShimFwrite(uint32_t ptr, uint32_t size, uint32_t n, uint32_t token,
                    uint32_t, uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (!f || !ptr) return 0;
  return uint32_t(std::fwrite(CPtr(ptr), size, n, f));
}

uint32_t ShimFseek(uint32_t token, uint32_t off, uint32_t whence, uint32_t,
                   uint32_t, uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (!f) return 0xFFFFFFFFu;
  return uint32_t(std::fseek(f, long(int32_t(off)), int(whence)));
}

uint32_t ShimFtell(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f ? uint32_t(std::ftell(f)) : 0xFFFFFFFFu;
}

uint32_t ShimFeof(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                  uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f ? uint32_t(std::feof(f)) : 1;
}

uint32_t ShimFerror(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f ? uint32_t(std::ferror(f)) : 1;
}

uint32_t ShimFflush(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (f) std::fflush(f);
  return 0;
}

uint32_t ShimClearerr(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                      uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (f) std::clearerr(f);
  return 0;
}

uint32_t ShimGetc(uint32_t token, uint32_t, uint32_t, uint32_t, uint32_t,
                  uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f ? uint32_t(int32_t(std::fgetc(f))) : 0xFFFFFFFFu;
}

uint32_t ShimUngetc(uint32_t ch, uint32_t token, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f ? uint32_t(int32_t(std::ungetc(int(ch), f))) : 0xFFFFFFFFu;
}

uint32_t ShimFgets(uint32_t buf, uint32_t n, uint32_t token, uint32_t,
                   uint32_t, uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  if (!f || !buf) return 0;
  return std::fgets(Ptr(buf), int(n), f) ? buf : 0;
}

uint32_t ShimFputc(uint32_t ch, uint32_t token, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f ? uint32_t(std::fputc(int(ch), f)) : 0xFFFFFFFFu;
}

uint32_t ShimFputs(uint32_t str, uint32_t token, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t, uint32_t) {
  FILE* f = HostFile(token);
  return f && str ? uint32_t(std::fputs(CPtr(str), f)) : 0xFFFFFFFFu;
}

uint32_t ShimRemove(uint32_t path, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  return path ? uint32_t(std::remove(CPtr(path))) : 0xFFFFFFFFu;
}

uint32_t ShimRename(uint32_t a1, uint32_t b1, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  return a1 && b1 ? uint32_t(std::rename(CPtr(a1), CPtr(b1))) : 0xFFFFFFFFu;
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
    {"_realloc", ShimRealloc},
    {"_free", ShimFree},
    {"_arc4random", ShimArc4Random},
    {"_exit", ShimExit},

    {"_memcpy", ShimMemcpy},        {"___memcpy_chk", ShimMemcpy},
    {"_memmove", ShimMemmove},      {"___memmove_chk", ShimMemmove},
    {"_memset", ShimMemset},        {"_memcmp", ShimMemcmp},
    {"_memchr", ShimMemchr},        {"_strlen", ShimStrlen},
    {"_strcmp", ShimStrcmp},        {"_strncmp", ShimStrncmp},
    {"_strcoll", ShimStrcoll},      {"_strcpy", ShimStrcpy},
    {"_strncpy", ShimStrncpy},      {"_strcat", ShimStrcat},
    {"_strncat", ShimStrncat},      {"_strchr", ShimStrchr},
    {"_strrchr", ShimStrrchr},      {"_strstr", ShimStrstr},
    {"_strpbrk", ShimStrpbrk},      {"_strcspn", ShimStrcspn},
    {"_strcasecmp", ShimStrcasecmp},{"_strtok", ShimStrtok},
    {"_strerror", ShimStrerror},    {"_strtol", ShimStrtol},
    {"_strtoul", ShimStrtoul},

    {"_abort", ShimAbort},          {"_rand", ShimRand},
    {"_srand", ShimSrand},          {"_time", ShimTime},
    {"_clock", ShimClock},          {"_system", ShimSystem},
    {"_gettimeofday", ShimGettimeofday},

    // Answering these with zero is the honest answer, not a stub: there is no
    // environment, no scheduler to yield to that matters, and sleeping in a
    // frame loop is the last thing wanted.
    {"_getenv", ShimNop},           {"_sched_yield", ShimNop},
    {"_usleep", ShimNop},           {"_setlocale", ShimNop},
    {"_localeconv", ShimNop},       {"___cxa_atexit", ShimNop},
    {"___error", ShimErrno},

    // C++. The sized and array forms allocate the same way.
    {"__Znwm", ShimNew},            {"__Znam", ShimNew},
    {"__ZdlPv", ShimDelete},        {"__ZdaPv", ShimDelete},

    // The unwinder. Registration is inert until something throws; throwing
    // is not answered quietly, because unwinding to the wrong place is worse
    // than stopping where the throw was.
    {"__Unwind_SjLj_Register", ShimUnwindNop},
    {"__Unwind_SjLj_Unregister", ShimUnwindNop},
    {"__Unwind_SjLj_Resume", ShimThrow},
    {"___cxa_throw", ShimThrow},
    {"___cxa_allocate_exception", ShimNew},
    {"___cxa_begin_catch", ShimUnwindNop},
    {"___cxa_end_catch", ShimUnwindNop},
    {"__ZSt9terminatev", ShimAbort},

    // A single-threaded guest synchronises with itself for free.
    {"_objc_sync_enter", ShimUnwindNop},
    {"_objc_sync_exit", ShimUnwindNop},

    {"_fopen", ShimFopen},          {"_fclose", ShimFclose},
    {"_fread", ShimFread},          {"_fwrite", ShimFwrite},
    {"_fseek", ShimFseek},          {"_ftell", ShimFtell},
    {"_feof", ShimFeof},            {"_ferror", ShimFerror},
    {"_fflush", ShimFflush},        {"_clearerr", ShimClearerr},
    {"_getc", ShimGetc},            {"_ungetc", ShimUngetc},
    {"_fgets", ShimFgets},          {"_fputc", ShimFputc},
    {"_fputs", ShimFputs},          {"_remove", ShimRemove},
    {"_rename", ShimRename},        {"_setvbuf", ShimNop},
};

const CtxShim kCtx[] = {
    {"_ceilf", ShimCeilf},   {"_floorf", ShimFloorf},
    {"_sin", ShimSin},       {"_cos", ShimCos},
    {"___divsi3", ShimDivsi3}, {"___modsi3", ShimModsi3},
    {"___umodsi3", ShimUmodsi3},

    {"_sinf", ShimSinf},     {"_cosf", ShimCosf},
    {"_tanf", ShimTanf},     {"_asinf", ShimAsinf},
    {"_acosf", ShimAcosf},   {"_atanf", ShimAtanf},
    {"_atan2f", ShimAtan2f}, {"_sinhf", ShimSinhf},
    {"_coshf", ShimCoshf},   {"_tanhf", ShimTanhf},
    {"_expf", ShimExpf},     {"_logf", ShimLogf},
    {"_log10f", ShimLog10f}, {"_powf", ShimPowf},
    {"_fmodf", ShimFmodf},   {"_ldexpf", ShimLdexpf},
    {"_pow", ShimPow},       {"_fmod", ShimFmod},
    {"_tan", ShimTan},
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
