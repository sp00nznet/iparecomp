# Architecture

## The pipeline

```
.ipa ──▶ ipa_probe.py ──▶ go / no-go
           │
           └─▶ macho_image ──▶ mapped image + import work list
                                  │
                                  ├─▶ shim + ObjC runtime  ──┐
                                  │                          ├─▶ native executable
                                  └─▶ decoder ──▶ emitter ───┘
```

Everything left of the emitter exists today. This document is mostly about what
the emitter has to do, because that is the part with real decisions in it.

## What the loader has to know that ELF did not

**Imports name their own framework.** Every undefined symbol in a Mach-O
carries a library ordinal in the top byte of `n_desc`, indexing the
`LC_LOAD_DYLIB` commands in order. So the work list is exact — `_glDrawArrays`
is *known* to be owed by OpenGLES, not guessed from a name prefix the way the
ELF side must. This is the one place iOS is kinder than Android.

**Addresses are absolute.** These binaries were linked to load at a fixed
address, and `__TEXT` vmaddr is meaningful. The loader records the slide
between that and where it actually mapped, and the emitter expresses every
PC-derived constant as `image_base + k`.

**`__TEXT` may be ciphertext.** Checked before anything else and reported as a
first-class state, because it is the most common reason a candidate is not
viable and it is invisible otherwise — an encrypted binary parses perfectly.

**There is no `LC_FUNCTION_STARTS`.** It postdates this era. The symbol table
is the only boundary evidence, which puts real coverage at 80–92% rather than
the 100% an `.eh_frame` gives, and makes the `N_ARM_THUMB_DEF` bit precious:
it is the only record of which instruction set a function is in.

## The emitter

One C function per guest function, as in androidrecomp. Guest pointers are host
pointers, so a guest load is a host dereference and there is no address
translation layer. Beyond that, 32-bit ARM forces four decisions that ARM64
never raised.

### 1. Every instruction is conditional

In ARM mode the top four bits of nearly every instruction are a condition code.
Emitting a branch per instruction would produce unreadable C and defeat the
host compiler's scheduler, so instead each instruction becomes a guarded
statement over the unpacked flags:

```c
if (ARC_COND_NE(c)) { ARC_W(c, 0, ARC_R(c, 1) + 4); }
```

`ARC_COND_*` are pure expressions over `nf`/`zf`/`cf`/`vf`, which the host
compiler routinely flattens into a conditional move. Unconditional
instructions (`cond == AL`, the overwhelming majority) emit no guard at all.

Thumb-2 does the same thing differently: an `it` instruction makes up to four
*following* instructions conditional, so the state lives between instructions
rather than inside them. The emitter resolves IT blocks statically — it knows
the block's extent at lift time — and only falls back to the runtime `itstate`
field when a branch target lands inside a block, which is rare and worth
trapping on rather than silently mis-lifting.

### 2. The PC is a general register

`r15` reads as the instruction's own address plus 8 in ARM, plus 4 in Thumb.
This is not an edge case: it is how every literal pool load works, and there
are 28,788 PC-relative operations in Angry Birds Rio alone.

The emitter never stores a PC. It knows the address of the instruction it is
lifting, so it folds the read into a constant at lift time:

```c
/* ldr r3, [pc, #0x40]  @ 0x00012a4c */
ARC_W(c, 3, ARC_LD32(c->image_base + 0x12a94));
```

Writing `r15` is a branch, and is emitted as one.

### 3. The barrel shifter has its own carry

Operand2 of most data-processing instructions is a register run through a
shifter, and the shifter produces a carry-out that is *not* the ALU carry. A
flag-setting logical instruction writes C from the shifter; the ALU never
produced one. `arc_lsl`/`arc_lsr`/`arc_asr`/`arc_ror`/`arc_rrx` return both
values, and non-flag-setting forms discard the carry so the host compiler drops
the computation.

The edge cases are all encodings the assembler actually emits: `LSR #0` means
`LSR #32`, `ROR #0` means `RRX`, and `LSL #0` is a pass-through that must leave
C alone. Getting the pass-through wrong clobbers the carry between a compare
and the instruction that consumes it.

Related, and the classic silent bug: **ARM's carry flag on subtraction is the
NOT-borrow.** `CMP 5, 3` sets C. Invert it and every unsigned comparison in the
game quietly goes the wrong way — no crash, just wrong behaviour deep in the
simulation. `tools/arc_selftest.c` exists mostly to nail this down, and it
forces `NDEBUG` off so a release build cannot make it vacuous.

### 4. A function does not end at `bx lr`

`ldm`/`pop` can write the PC, which is how most functions of this era return:
`pop {r4, r5, pc}`. So the emitter cannot treat `bx lr` as the terminator. It
classifies a PC-writing block transfer by its register list — a load from the
stack that ends the frame is a return; anything else is an indirect branch and
goes through the dispatcher.

11,179 block transfers in Angry Birds Rio, 7,307 interworking branches. Neither
is rare.

### Interworking and the dispatcher

`bx`/`blx` select the instruction set from the low bit of the target. The
dispatch table is keyed on the masked address, and the bit is checked against
the mode the lifter recorded for that function. A mismatch is a trap, not a
guess — a Thumb function entered as ARM decodes as garbage that runs, which is
far worse than stopping.

```c
#define ARC_THUMB_BIT(target) ((target) & 1u)
#define ARC_CODE_ADDR(target) ((target) & ~1u)
```

A binary that is 100% one instruction set never exercises any of this, which is
exactly why the first port is one.

### What is not lifted at all

`objc_msgSend` is the most-executed function in any iOS binary and its entire
job is a runtime lookup. Lifting it would be pointless even if it were
possible. It is a shim boundary: the emitter emits a call to `arc_msg_send`
with the guest's registers exactly as arranged — receiver in `r0`, selector in
`r1`, arguments after.

This is the load-bearing shortcut of the whole design. The Objective-C half of
the app is answered by a runtime; the C and C++ half is compiled. A game with
38 classes and 866 selectors has a far smaller ObjC surface than its
framework list implies, because the frameworks are consumed *through* that one
call rather than lifted.

The same applies to `libSystem`, `libstdc++` and `libgcc` imports: they are
resolved by name against the host C runtime wherever the signature matches,
which is most of them.

## Verification

The emitter is checked the way androidrecomp checks its own: differentially,
against an independent oracle, on real harvested instructions rather than
synthetic ones. Unicorn provides the oracle and needs no armv6 hardware, which
is fortunate, because there is none.

Per-instruction first, then whole functions with the image mapped at the same
address on both sides. A lifted function that agrees with the emulator on
registers, flags and memory for real inputs is correct in the only sense that
matters.

## The shim surface

Measured, not estimated. Canabalt's 205 undefined symbols, grouped by the
framework that owes them:

| framework | n | note |
|---|---|---|
| OpenGLES | 39 | desktop GL exports most of GLES 1.1 under identical names |
| CoreGraphics | 38 | images, contexts, transforms |
| UIKit | 27 | window, view, touch, run loop — SDL2 underneath |
| Foundation | 20 | mostly answered by the ObjC runtime, not by C shims |
| OpenAL | 14 | link native openal-soft |
| CoreFoundation | 14 | CFString/CFDictionary/CFRunLoop |
| Security | 12 | keychain; stubbable |
| libSystem.B.dylib | 10 | host C runtime, by name |
| libobjc.A.dylib | 9 | the runtime itself |
| AudioToolbox | 8 | audio file decode |
| CoreData | 8 | stubbable |
| libgcc_s.1.dylib | 3 | unwinder |
| QuartzCore | 2 | CADisplayLink, CAEAGLLayer |
| AVFoundation | 1 | `AVAudioPlayer`; one class |

Angry Birds Rio is 354 across the same shape, of which 136 are `libSystem` —
that is, C library, nearly free. The real work in both is OpenGLES, UIKit and
the ObjC runtime, and all three are shared across every port.

That sharing is the point of keeping this repo app-agnostic. The second port
should cost a fraction of the first.
