// Guest CPU state for lifted ARM/Thumb code, and the operations lifted code
// emits. This header is the emitter's target: everything tools/lifter.py
// generates is a call into, or a macro from, this file.
//
// As in androidrecomp, there is no address translation. The loader maps the
// image at a real host address and the shim hands the guest the host's own
// malloc, so a guest load is a host dereference. What is *not* position
// independent is any address the instruction stream computes from the PC, and
// on 32-bit ARM that is a great deal more than on ARM64 -- see below.
//
// Four things make this meaningfully harder than the ARM64 context, and each
// costs something here:
//
//   1. The PC is a general register (r15). Reading it yields the instruction's
//      own address plus 8 in ARM and plus 4 in Thumb, and writing it is a
//      branch. Lifted code never stores r15 in the array; the emitter folds
//      every PC read into a constant at lift time, because it knows where the
//      instruction was.
//   2. Every ARM instruction is conditional. The emitter wraps each one in a
//      predicate built from the unpacked flags rather than emitting a branch.
//   3. The barrel shifter produces a carry-out that is *not* the ALU carry.
//      Shift helpers return it separately, and only flag-setting forms consume
//      it.
//   4. `ldm`/`pop` can write the PC, so a function does not reliably end at
//      `bx lr`. The emitter treats a PC-writing block transfer as a return or
//      an indirect branch depending on the register list.
#pragma once

#include <math.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// VFPv2 on armv6, NEON on armv7. The register files alias: s[2n]/s[2n+1] are
// the halves of d[n], and q[n] is d[2n]/d[2n+1]. One array, many views, so an
// aliased write through any of them is visible to the others -- which is what
// the hardware does and what NEON code relies on.
typedef union {
  uint64_t u64[32];   // d0-d31
  int64_t i64[32];
  double f64[32];
  uint32_t u32[64];   // s0-s31 occupy the first 32 of these
  int32_t i32[64];
  float f32[64];
  uint16_t u16[128];
  uint8_t u8[256];
} Arm32VecFile;

typedef struct Arm32Ctx {
  // r[15] is the PC. It exists so that a struct offset matches a register
  // number, but lifted code never reads or writes it: PC reads are folded to
  // constants and PC writes are branches. Reading it should be treated as a
  // bug in the emitter, not a value.
  uint32_t r[16];

  // NZCV, kept unpacked. Nothing reads them as a word, and keeping them apart
  // means a flag-setting instruction writes four independent variables the
  // host compiler can forward, instead of a packed CPSR nobody can see into.
  uint32_t nf, zf, cf, vf;
  uint32_t qf;  // saturation sticky bit, set by QADD/SSAT and friends

  Arm32VecFile v;
  uint32_t fpscr;

  // Where the image was mapped. Every address the instruction stream derived
  // from the PC -- literal pool loads, adr, the constants behind
  // position-independent stubs -- is emitted as image_base + a constant.
  uint32_t image_base;

  // Thumb IT-block state. Thumb-2 makes up to four instructions conditional
  // with one preceding `it` instruction, and unlike ARM's per-instruction
  // condition field, that state lives *between* instructions. The emitter
  // resolves IT blocks statically where the block does not span a branch
  // target, and falls back to this when it does.
  uint32_t itstate;
} Arm32Ctx;

// --- register access -------------------------------------------------------
// No zero register on this architecture, so these are plain accesses. They
// exist so the emitter has one spelling to change, and so that a read of r15
// can be trapped in a debug build.
#define ARC_R(c, n) ((c)->r[(n)])
#define ARC_W(c, n, val) ((void)((c)->r[(n)] = (uint32_t)(val)))
#define ARC_SP(c) ((c)->r[13])
#define ARC_LR(c) ((c)->r[14])

// --- condition codes -------------------------------------------------------
// The cond field of every ARM instruction, and of Thumb's `it`. Emitted as a
// guard expression around the instruction body, so a predicated instruction
// costs a branch the host compiler can usually flatten into a cmov.
#define ARC_COND_EQ(c) ((c)->zf)
#define ARC_COND_NE(c) (!(c)->zf)
#define ARC_COND_CS(c) ((c)->cf)
#define ARC_COND_CC(c) (!(c)->cf)
#define ARC_COND_MI(c) ((c)->nf)
#define ARC_COND_PL(c) (!(c)->nf)
#define ARC_COND_VS(c) ((c)->vf)
#define ARC_COND_VC(c) (!(c)->vf)
#define ARC_COND_HI(c) ((c)->cf && !(c)->zf)
#define ARC_COND_LS(c) (!(c)->cf || (c)->zf)
#define ARC_COND_GE(c) ((c)->nf == (c)->vf)
#define ARC_COND_LT(c) ((c)->nf != (c)->vf)
#define ARC_COND_GT(c) (!(c)->zf && (c)->nf == (c)->vf)
#define ARC_COND_LE(c) ((c)->zf || (c)->nf != (c)->vf)
#define ARC_COND_AL(c) (1)

// --- flags -----------------------------------------------------------------
#define ARC_NZ(c, res)                     \
  do {                                     \
    (c)->nf = ((uint32_t)(res)) >> 31;     \
    (c)->zf = ((uint32_t)(res)) == 0;      \
  } while (0)

static inline void arc_add_flags(Arm32Ctx* c, uint32_t a, uint32_t b, uint32_t carry_in) {
  uint64_t wide = (uint64_t)a + (uint64_t)b + carry_in;
  uint32_t res = (uint32_t)wide;
  ARC_NZ(c, res);
  c->cf = (uint32_t)(wide >> 32);
  c->vf = (~(a ^ b) & (a ^ res)) >> 31;
}

static inline void arc_sub_flags(Arm32Ctx* c, uint32_t a, uint32_t b, uint32_t carry_in) {
  // SUB is ADD of the complement; the carry-in is the NOT-borrow, which is why
  // `cmp` sets C on *no* borrow. Getting this backwards is the classic 32-bit
  // ARM lifting bug and it only shows up in unsigned comparisons.
  uint64_t wide = (uint64_t)a + (uint64_t)(~b) + carry_in;
  uint32_t res = (uint32_t)wide;
  ARC_NZ(c, res);
  c->cf = (uint32_t)(wide >> 32);
  c->vf = ((a ^ b) & (a ^ res)) >> 31;
}

// --- barrel shifter --------------------------------------------------------
// Operand2 of most data-processing instructions is a register run through a
// shifter, and the shifter emits its own carry-out. That carry is what a
// flag-setting logical instruction writes to C -- the ALU never produced one.
// These return the shifted value and write the carry through a pointer, so a
// non-flag-setting form can pass NULL and the host compiler drops the store.
typedef struct { uint32_t value, carry; } ArcShift;

static inline ArcShift arc_lsl(uint32_t v, uint32_t n, uint32_t cin) {
  ArcShift r;
  if (n == 0) { r.value = v; r.carry = cin; }
  else if (n < 32) { r.value = v << n; r.carry = (v >> (32 - n)) & 1; }
  else if (n == 32) { r.value = 0; r.carry = v & 1; }
  else { r.value = 0; r.carry = 0; }
  return r;
}

static inline ArcShift arc_lsr(uint32_t v, uint32_t n, uint32_t cin) {
  ArcShift r;
  if (n == 0) { r.value = v; r.carry = cin; }
  else if (n < 32) { r.value = v >> n; r.carry = (v >> (n - 1)) & 1; }
  else if (n == 32) { r.value = 0; r.carry = v >> 31; }
  else { r.value = 0; r.carry = 0; }
  return r;
}

static inline ArcShift arc_asr(uint32_t v, uint32_t n, uint32_t cin) {
  ArcShift r;
  if (n == 0) { r.value = v; r.carry = cin; }
  else if (n < 32) {
    r.value = (uint32_t)((int32_t)v >> n);
    r.carry = (v >> (n - 1)) & 1;
  } else {
    r.value = (uint32_t)((int32_t)v >> 31);
    r.carry = v >> 31;
  }
  return r;
}

static inline ArcShift arc_ror(uint32_t v, uint32_t n, uint32_t cin) {
  // The zero test happens *before* the mask, and that distinction is the whole
  // subtlety: ROR by 32, 64 or 96 leaves the value alone but still writes C
  // from bit 31, while ROR by 0 must leave C untouched. Masking first collapses
  // the two and quietly carries a stale flag into the next conditional.
  ArcShift r;
  if (n == 0) { r.value = v; r.carry = cin; return r; }
  n &= 31;
  if (n == 0) { r.value = v; r.carry = v >> 31; }
  else { r.value = (v >> n) | (v << (32 - n)); r.carry = (r.value >> 31) & 1; }
  return r;
}

// RRX: a 33-bit rotate through the carry flag. One bit, no shift amount.
static inline ArcShift arc_rrx(uint32_t v, uint32_t cin) {
  ArcShift r;
  r.value = (v >> 1) | (cin << 31);
  r.carry = v & 1;
  return r;
}

// --- VFP -------------------------------------------------------------------
// The register file aliases, so these are views rather than conversions:
// s[2n] and s[2n+1] are the halves of d[n], which is what the hardware does
// and what the calling convention relies on when a double is passed in two
// single registers.
#define ARC_S(c, n) ((c)->v.f32[(n)])
#define ARC_D(c, n) ((c)->v.f64[(n)])
#define ARC_SU(c, n) ((c)->v.u32[(n)])
#define ARC_DU(c, n) ((c)->v.u64[(n)])

// Three places C and the hardware disagree, each producing a plausible wrong
// number rather than a crash. Inherited from androidrecomp, which found all
// three the expensive way.
//
// 1. An invalid operation -- 0/0, inf - inf, 0 * inf -- yields a NaN whose
//    sign bit x86 sets and ARM clears. It affects all four basic operations,
//    not just sqrt. ARM returns its *default* NaN, which is positive.
// 2. Float-to-integer saturates on ARM and is undefined behaviour in C once
//    the value does not fit, so it cannot be written as a cast at all.
// 3. (No vmin/vmax in the armv6 encodings these binaries use. If a later
//    target brings them: ARM propagates NaN, C's fmin/fmax deliberately do
//    not, and only fminnm/fmaxnm match C.)
#define ARC_DEFAULT_NAN_F32 0x7FC00000u
#define ARC_DEFAULT_NAN_F64 0x7FF8000000000000ull

static inline float arc_dnan_f32(void) {
  union { uint32_t u; float f; } x;
  x.u = ARC_DEFAULT_NAN_F32;
  return x.f;
}

static inline double arc_dnan_f64(void) {
  union { uint64_t u; double f; } x;
  x.u = ARC_DEFAULT_NAN_F64;
  return x.f;
}

// A NaN the operation *generated* rather than propagated is the default NaN.
// A NaN that came in from an operand is passed through as the hardware would.
#define ARC_FP_OP(T, SUFFIX, EXPR)                                        \
  static inline T arc_##SUFFIX(T a, T b) {                                \
    T r = (EXPR);                                                         \
    if ((r != r) && (a == a) && (b == b)) return arc_dnan_##T##_();       \
    return r;                                                             \
  }

static inline float arc_dnan_float_(void) { return arc_dnan_f32(); }
static inline double arc_dnan_double_(void) { return arc_dnan_f64(); }

ARC_FP_OP(float, addf32, a + b)
ARC_FP_OP(float, subf32, a - b)
ARC_FP_OP(float, mulf32, a * b)
ARC_FP_OP(float, divf32, a / b)
ARC_FP_OP(double, addf64, a + b)
ARC_FP_OP(double, subf64, a - b)
ARC_FP_OP(double, mulf64, a * b)
ARC_FP_OP(double, divf64, a / b)

static inline float arc_sqrtf32(float a) {
  if (a < 0.0f) return arc_dnan_f32();
  return (float)sqrt((double)a);
}

static inline double arc_sqrtf64(double a) {
  if (a < 0.0) return arc_dnan_f64();
  return sqrt(a);
}

// Saturating, and never a bare cast: the out-of-range case is undefined
// behaviour in C, which in practice means the optimiser is entitled to assume
// it cannot happen and delete the guard you wrote after the cast.
static inline uint32_t arc_f32_to_s32(float v) {
  if (v != v) return 0;
  if (v >= 2147483648.0f) return 0x7FFFFFFFu;
  if (v < -2147483648.0f) return 0x80000000u;
  return (uint32_t)(int32_t)v;
}

static inline uint32_t arc_f32_to_u32(float v) {
  if (v != v || v <= 0.0f) return 0;
  if (v >= 4294967296.0f) return 0xFFFFFFFFu;
  return (uint32_t)v;
}

static inline uint32_t arc_f64_to_s32(double v) {
  if (v != v) return 0;
  if (v >= 2147483648.0) return 0x7FFFFFFFu;
  if (v < -2147483648.0) return 0x80000000u;
  return (uint32_t)(int32_t)v;
}

static inline uint32_t arc_f64_to_u32(double v) {
  if (v != v || v <= 0.0) return 0;
  if (v >= 4294967296.0) return 0xFFFFFFFFu;
  return (uint32_t)v;
}

// A VFP compare writes FPSCR, not the core flags, and a separate `vmrs
// apsr_nzcv, fpscr` moves them across. Keeping that two-step is not pedantry:
// there are usually several instructions between the compare and the transfer,
// and collapsing them would let an intervening integer instruction that sets
// flags be silently overwritten.
#define ARC_FPSCR_N 0x80000000u
#define ARC_FPSCR_Z 0x40000000u
#define ARC_FPSCR_C 0x20000000u
#define ARC_FPSCR_V 0x10000000u

static inline uint32_t arc_fp_compare(int lt, int eq, int unordered) {
  // Unordered sets C and V and clears N and Z, which is what makes an
  // unsigned-style condition (`hi`, `ls`) the way a NaN-safe float comparison
  // is spelled on this architecture.
  if (unordered) return ARC_FPSCR_C | ARC_FPSCR_V;
  if (eq) return ARC_FPSCR_Z | ARC_FPSCR_C;
  if (lt) return ARC_FPSCR_N;
  return ARC_FPSCR_C;
}

static inline void arc_vcmp_f32(Arm32Ctx* c, float a, float b) {
  c->fpscr = (c->fpscr & 0x0FFFFFFFu) |
             arc_fp_compare(a < b, a == b, (a != a) || (b != b));
}

static inline void arc_vcmp_f64(Arm32Ctx* c, double a, double b) {
  c->fpscr = (c->fpscr & 0x0FFFFFFFu) |
             arc_fp_compare(a < b, a == b, (a != a) || (b != b));
}

static inline void arc_vmrs_nzcv(Arm32Ctx* c) {
  c->nf = (c->fpscr & ARC_FPSCR_N) != 0;
  c->zf = (c->fpscr & ARC_FPSCR_Z) != 0;
  c->cf = (c->fpscr & ARC_FPSCR_C) != 0;
  c->vf = (c->fpscr & ARC_FPSCR_V) != 0;
}

// --- memory ----------------------------------------------------------------
// Guest pointers are host pointers, so these are dereferences with the guest's
// width and signedness. They exist as functions rather than casts so that a
// bring-up build can bounds-check every access against the mapped image.
#define ARC_LD8(a)  (*(uint8_t*)(uintptr_t)(a))
#define ARC_LD8S(a) ((uint32_t)(int32_t)*(int8_t*)(uintptr_t)(a))
#define ARC_LD16(a) (*(uint16_t*)(uintptr_t)(a))
#define ARC_LD16S(a) ((uint32_t)(int32_t)*(int16_t*)(uintptr_t)(a))
#define ARC_LD32(a) (*(uint32_t*)(uintptr_t)(a))
// A doubleword access is two words in the guest's eyes and is only ever
// 4-byte aligned, so it is spelled as two rather than as one unaligned 64-bit
// dereference the host may not permit.
#define ARC_LD64(a) ((uint64_t)ARC_LD32(a) | ((uint64_t)ARC_LD32((a) + 4) << 32))
#define ARC_ST64(a, v)                                     do {                                                       const uint64_t v_ = (uint64_t)(v);                       ARC_ST32((a), (uint32_t)v_);                             ARC_ST32((a) + 4, (uint32_t)(v_ >> 32));               } while (0)
#define ARC_ST8(a, v)  (*(uint8_t*)(uintptr_t)(a) = (uint8_t)(v))
#define ARC_ST16(a, v) (*(uint16_t*)(uintptr_t)(a) = (uint16_t)(v))
#define ARC_ST32(a, v) (*(uint32_t*)(uintptr_t)(a) = (uint32_t)(v))

// --- control flow ----------------------------------------------------------
// A guest trap: an undefined instruction, or an indirect branch that resolves
// to nothing. Loud on purpose -- reaching one means the lift is incomplete.
void arc_trap(Arm32Ctx* c, const char* what);
void arc_set_recovery(void* jmp_buffer);
const char* arc_last_trap(void);

// Calling out of the guest. An import is reached the way a virtual method is:
// the guest loads a stub pointer and branches to it. That address is a *host*
// function the shim supplied, so it will never be in the lifted table.
// The guest reaches an import by branching to its stub, so the *stub address*
// is the name the runtime knows it by -- but that address is a 32-bit number
// in guest space and the host function is not reachable through it. The two
// have to be registered together. "Resolved" never means "is a host function".
typedef uint32_t (*ArcNativeFn)(uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t, uint32_t, uint32_t);
void arc_register_native(uint32_t address, const char* name, ArcNativeFn fn);

// The fuller form: everything the plain thunk cannot express -- a float
// argument, a struct return, or anything that has to see the guest's own
// registers. objc_msgSend is one of these.
typedef void (*ArcCtxFn)(Arm32Ctx*);
void arc_register_ctx_native(uint32_t address, const char* name, ArcCtxFn fn);

// An import that exists and has no implementation yet. Registering these is
// what turns "indirect branch to 0x3aee4, neither lifted nor a known import"
// into the name of the next thing to write. The distinction matters: an
// unknown address is a bug in the lift, whereas a named unimplemented import
// is simply work, and the two want telling apart at a glance.
void arc_register_stub(uint32_t address, const char* name, const char* owner);

// Answer an unimplemented import with zero and record it, rather than
// stopping. The same measuring instrument the Objective-C side has: one run
// then names every missing import as well as every missing message, instead of
// one rebuild per symbol.
void arc_set_permissive(int on);

// A guest that never finishes reports nothing, which during bring-up is the
// least useful outcome there is. Every lifted function entry counts against a
// budget; exhausting it traps, so the frame ring and the call trail survive
// and say where it was going round.
//
// The frame loop resets it, because a game that is running is *supposed* to
// enter functions forever -- the budget is about reaching the loop, not about
// staying in it.
// The context the guest is running on, so a fault handler can say what was in
// the registers. A faulting address on its own says which byte was touched;
// the registers say which value was used as a pointer, and that is usually the
// difference between a diagnosis and a guess.
void arc_set_current_context(Arm32Ctx* c);
Arm32Ctx* arc_current_context(void);

void arc_frame_budget(long entries);
void arc_frame_budget_reset(void);
size_t arc_missing_count(void);
const char* arc_missing_at(size_t i);

// Interworking. `bx`/`blx` select the instruction set from the low bit of the
// target, so the dispatcher must mask it off to find the function and must not
// lose it -- a Thumb function lifted as ARM decodes as garbage. The lifted
// table is keyed on the masked address; the bit is checked against what the
// lifter recorded for that function, and a mismatch is a trap, not a guess.
#define ARC_THUMB_BIT(target) ((target) & 1u)
#define ARC_CODE_ADDR(target) ((target) & ~1u)

// The library owns `arc_dispatch` because the shim itself has to dispatch -- a
// guest callback or thread entry point is a guest address, not a host
// function. But only the generated module knows the address -> function table,
// so it installs its own here. Anything the shim calls is *defined* in the
// library; anything generated *plugs in*.
typedef void (*ArcDispatchFn)(Arm32Ctx*, uint32_t);
void arc_set_dispatch(ArcDispatchFn fn);

void arc_dispatch(Arm32Ctx* c, uint32_t target);
void arc_dispatch_miss(Arm32Ctx* c, uint32_t target);

// --- Objective-C -----------------------------------------------------------
// objc_msgSend is not lifted. It is the single most-executed function in any
// iOS binary and its whole job is a runtime lookup, so the lifter emits a call
// to the runtime here instead: receiver in r0, selector in r1, arguments in
// r2..r3 and on the stack, exactly as the guest arranged them.
//
// This is the load-bearing shortcut of the whole design. It means the ObjC
// half of the app is *interpreted* against a real runtime while the C/C++ half
// is compiled, and it is why a game with 38 classes and 866 selectors is a
// far smaller job than the framework list makes it look.
void arc_msg_send(Arm32Ctx* c);

// --- what the guest was doing ----------------------------------------------
// The library always defines this; ARC_FRAMES only decides whether generated
// code calls it. One store per lifted call when it is on, nothing when it is
// not.
void arc_frame_note(uint32_t packed);
#if !defined(ARC_FRAMES)
#define arc_frame_note(packed) ((void)0)
#endif
size_t arc_frame_count(void);
uint32_t arc_frame_at(size_t back);

// Who called it. Captured from lr at entry, before the prologue saves it, so
// a ring of entries becomes a ring of call *edges* -- which is the difference
// between knowing a function ran and knowing what asked it to. Zero when
// nothing was recorded.
uint32_t arc_frame_caller(size_t back);
void arc_frame_clear(void);
void arc_trace_note(const char* name);
size_t arc_trace_count(void);
const char* arc_trace_at(size_t back);
void arc_trace_clear(void);

#ifdef __cplusplus
}
#endif
