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
  ArcShift r;
  n &= 31;
  if (n == 0) { r.value = v; r.carry = cin; }
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

// --- memory ----------------------------------------------------------------
// Guest pointers are host pointers, so these are dereferences with the guest's
// width and signedness. They exist as functions rather than casts so that a
// bring-up build can bounds-check every access against the mapped image.
#define ARC_LD8(a)  (*(uint8_t*)(uintptr_t)(a))
#define ARC_LD8S(a) ((uint32_t)(int32_t)*(int8_t*)(uintptr_t)(a))
#define ARC_LD16(a) (*(uint16_t*)(uintptr_t)(a))
#define ARC_LD16S(a) ((uint32_t)(int32_t)*(int16_t*)(uintptr_t)(a))
#define ARC_LD32(a) (*(uint32_t*)(uintptr_t)(a))
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
void arc_register_native(uint32_t address, const char* name);
typedef void (*ArcCtxFn)(Arm32Ctx*);
void arc_register_ctx_native(uint32_t address, const char* name, ArcCtxFn fn);

// Interworking. `bx`/`blx` select the instruction set from the low bit of the
// target, so the dispatcher must mask it off to find the function and must not
// lose it -- a Thumb function lifted as ARM decodes as garbage. The lifted
// table is keyed on the masked address; the bit is checked against what the
// lifter recorded for that function, and a mismatch is a trap, not a guess.
#define ARC_THUMB_BIT(target) ((target) & 1u)
#define ARC_CODE_ADDR(target) ((target) & ~1u)

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
#if defined(ARC_FRAMES)
void arc_frame_note(uint32_t packed);
#else
#define arc_frame_note(packed) ((void)0)
#endif
size_t arc_frame_count(void);
uint32_t arc_frame_at(size_t back);
void arc_frame_clear(void);
void arc_trace_note(const char* name);
size_t arc_trace_count(void);
const char* arc_trace_at(size_t back);
void arc_trace_clear(void);

#ifdef __cplusplus
}
#endif
