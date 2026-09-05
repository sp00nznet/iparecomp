// Self-check for the parts of arm32_context.h that are easy to get wrong and
// silent when wrong: the barrel shifter's carry-out, and the fact that ARM's
// carry flag on a subtract is the NOT-borrow.
//
// Every expected value here is what real ARM hardware produces. If one of
// these trips, the emitter is generating correct-looking C that computes the
// wrong flags, and the symptom will be an unsigned comparison going the wrong
// way somewhere deep in a game -- not a crash.
//
//   cc -I runtime tools/arc_selftest.c -o arc_selftest && ./arc_selftest
// A release build defines NDEBUG, which would compile every check below into
// nothing and leave this printing "ok" unconditionally. The whole point is to
// fail, so assertions are forced on regardless of build type.
#undef NDEBUG
#include <assert.h>
#include <stdio.h>

#include "arm32_context.h"

// The context header declares these; the runtime provides them. A standalone
// check does not link the runtime, so they are stubbed.
void arc_trap(Arm32Ctx* c, const char* what) { (void)c; (void)what; }

static void shifter(void) {
  // LSL #0 passes the carry through untouched -- it is not a shift at all.
  assert(arc_lsl(0x12345678u, 0, 1).carry == 1);
  assert(arc_lsl(0x12345678u, 0, 0).carry == 0);
  assert(arc_lsl(0x12345678u, 0, 1).value == 0x12345678u);

  // LSL #1 of 0x80000000 shifts the top bit out into C.
  assert(arc_lsl(0x80000000u, 1, 0).value == 0);
  assert(arc_lsl(0x80000000u, 1, 0).carry == 1);

  // LSL #32 is a real encoding: result 0, carry is bit 0.
  assert(arc_lsl(1u, 32, 0).value == 0);
  assert(arc_lsl(1u, 32, 0).carry == 1);
  assert(arc_lsl(2u, 32, 0).carry == 0);
  // Beyond 32 everything is gone, carry included.
  assert(arc_lsl(0xFFFFFFFFu, 33, 1).value == 0);
  assert(arc_lsl(0xFFFFFFFFu, 33, 1).carry == 0);

  // LSR #32 yields 0 with carry from bit 31. LSR #0 is *encoded* as LSR #32,
  // which is why the zero case must pass the carry through instead.
  assert(arc_lsr(0x80000000u, 32, 0).value == 0);
  assert(arc_lsr(0x80000000u, 32, 0).carry == 1);
  assert(arc_lsr(0x0F0F0F0Fu, 4, 0).value == 0x00F0F0F0u);
  assert(arc_lsr(0x0F0F0F0Fu, 4, 0).carry == 1);  // bit 3 of the source

  // ASR replicates the sign bit, and ASR >= 32 saturates to all-sign.
  assert(arc_asr(0x80000000u, 32, 0).value == 0xFFFFFFFFu);
  assert(arc_asr(0x80000000u, 32, 0).carry == 1);
  assert(arc_asr(0x7FFFFFFFu, 40, 0).value == 0);
  assert(arc_asr(0xFFFFFFF0u, 4, 0).value == 0xFFFFFFFFu);

  // ROR is modulo 32; ROR #0 is the encoding for RRX, so it passes through.
  assert(arc_ror(0x0000000Fu, 4, 0).value == 0xF0000000u);
  assert(arc_ror(0x0000000Fu, 4, 0).carry == 1);
  assert(arc_ror(0x12345678u, 0, 1).carry == 1);
  /* ROR by a register amount that is a multiple of 32 is not ROR #0. The value
     is unchanged either way, but the flag is not: a multiple of 32 writes C
     from bit 31 and only a true zero leaves C alone. Mask the amount before
     testing it for zero and the two collapse, which loses a carry between a
     shift and the conditional that consumes it. */
  assert(arc_ror(0x80000000u, 32, 0).value == 0x80000000u);
  assert(arc_ror(0x80000000u, 32, 0).carry == 1);
  assert(arc_ror(0x7FFFFFFFu, 64, 1).carry == 0);
  assert(arc_ror(0x80000000u, 0, 0).carry == 0);

  // RRX rotates through carry: one bit, carry in at the top, bit 0 out.
  assert(arc_rrx(0x00000001u, 1).value == 0x80000000u);
  assert(arc_rrx(0x00000001u, 1).carry == 1);
  assert(arc_rrx(0x00000002u, 0).value == 0x00000001u);
  assert(arc_rrx(0x00000002u, 0).carry == 0);
}

static void flags(void) {
  Arm32Ctx c;
  memset(&c, 0, sizeof c);

  // 1 + 1: no carry, no overflow.
  arc_add_flags(&c, 1, 1, 0);
  assert(!c.cf && !c.vf && !c.zf && !c.nf);

  // Unsigned wrap sets C. Signed does not overflow here.
  arc_add_flags(&c, 0xFFFFFFFFu, 1, 0);
  assert(c.cf && c.zf && !c.vf);

  // Signed overflow with no unsigned carry: 0x7FFFFFFF + 1.
  arc_add_flags(&c, 0x7FFFFFFFu, 1, 0);
  assert(c.vf && !c.cf && c.nf);

  // The one that matters. CMP 5, 3 -- ARM sets C when there is NO borrow, so
  // a >= b unsigned means C set. Get this inverted and every unsigned
  // comparison in the game silently flips.
  arc_sub_flags(&c, 5, 3, 1);
  assert(c.cf && !c.zf && !c.nf);

  // CMP 3, 5 borrows, so C is clear and the result is negative.
  arc_sub_flags(&c, 3, 5, 1);
  assert(!c.cf && c.nf && !c.zf);

  // Equal operands: zero result, and C set because there was no borrow.
  arc_sub_flags(&c, 7, 7, 1);
  assert(c.zf && c.cf && !c.nf);

  // Signed overflow on subtract: INT_MIN - 1.
  arc_sub_flags(&c, 0x80000000u, 1, 1);
  assert(c.vf);
}

static void aliasing(void) {
  // s[2n]/s[2n+1] must be the halves of d[n], and NEON code depends on it.
  Arm32Ctx c;
  memset(&c, 0, sizeof c);
  c.v.u64[3] = 0xAABBCCDD11223344ull;
  assert(c.v.u32[6] == 0x11223344u);   // little-endian low half
  assert(c.v.u32[7] == 0xAABBCCDDu);
  c.v.f32[0] = 1.0f;
  assert(c.v.u32[0] == 0x3F800000u);
}

static void interworking(void) {
  // The low bit selects the instruction set and must never reach the table.
  assert(ARC_CODE_ADDR(0x00012345u) == 0x00012344u);
  assert(ARC_THUMB_BIT(0x00012345u) == 1u);
  assert(ARC_CODE_ADDR(0x00012344u) == 0x00012344u);
  assert(ARC_THUMB_BIT(0x00012344u) == 0u);
}

int main(void) {
  shifter();
  flags();
  aliasing();
  interworking();
  puts("ok -- shifter carry, subtract-is-not-borrow, vector aliasing, interworking");
  return 0;
}
