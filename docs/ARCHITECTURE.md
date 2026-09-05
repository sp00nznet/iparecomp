# Architecture

## The pipeline

```
.ipa ──▶ ipa_probe.py ──▶ go / no-go
           │
           └─▶ macho_image ──▶ mapped image + import work list
                                  │
                                  ├─▶ shim + ObjC runtime  ──┐
                                  │                          ├─▶ native executable
                                  └─▶ lifter.py ─────────────┘
                                        │
                                        └─▶ lift_verify.py ──▶ Unicorn
```

Everything except the shim and the ObjC runtime exists today. This document is
mostly about the emitter, because that is the part with real decisions in it.

## What the loader has to know that ELF did not

**Imports name their own framework.** Every undefined symbol in a Mach-O
carries a library ordinal in the top byte of `n_desc`, indexing the
`LC_LOAD_DYLIB` commands in order. So the work list is exact — `_glDrawArrays`
is *known* to be owed by OpenGLES, not guessed from a name prefix the way the
ELF side must. This is the one place iOS is kinder than Android.

**Addresses are absolute, and that is not a stylistic difference.** These
binaries were linked to load at a fixed address, and `__TEXT` vmaddr is
meaningful. The emitter expresses every PC-derived constant as `image_base + k`
so that the generated code says what it depends on -- but see
[The slide has to be zero](#the-slide-has-to-be-zero), which is the constraint
that machinery cannot lift on its own.

**`__TEXT` may be ciphertext.** Checked before anything else and reported as a
first-class state, because it is the most common reason a candidate is not
viable and it is invisible otherwise — an encrypted binary parses perfectly.

**There is no `LC_FUNCTION_STARTS`.** It postdates this era. The symbol table
is the only boundary evidence, which puts real coverage at 80–92% rather than
the 100% an `.eh_frame` gives, and makes the `N_ARM_THUMB_DEF` bit precious:
it is the only record of which instruction set a function is in.

## The slide has to be zero

This is the sharpest constraint in the project and it was found by the
whole-function harness rather than by reading, so it is written down here
before it is solved.

Canabalt's binary is `MH_EXECUTE`, **not** `MH_PIE`, and it carries no
relocation information of any kind:

```
  rebase     off 0x0        size 0
  bind       off 0x43000    size 2,852
  lazy_bind  off 0x43b24    size 3,100
  dysymtab: 0 external relocs, 0 local relocs
```

The bind tables are there, because imports still had to be resolved. The
*rebase* table is empty, because it was never needed: a non-PIE executable of
this era was linked at a fixed address and dyld never slid it. Nothing in the
file records which words are pointers.

So a pointer in `__DATA`, or a pointer sitting in a literal pool in `__TEXT`,
is a bare link-time address like `0x00041a9c` with nothing marking it as one.
An image mapped anywhere else cannot be corrected, because there is no list of
what to correct. **The image has to be mapped at its own link address, and
`image_base` has to equal the link base.**

`__TEXT` begins at `0x1000`. Windows will not allocate below `0x10000` -- the
first 64 KB is the null-pointer partition and `VirtualAlloc` refuses it -- and
Linux refuses below `vm.mmap_min_addr`, 64 KB by default. Both floors sit above
the address this image needs.

What this costs today is measurable: of 152 self-contained functions in
Canabalt, 12 can be differentially tested. The other 140 dereference a
link-absolute pointer, which in a slid harness is a wild read. It is not a
harness defect -- it is the real constraint, showing up early.

Three ways out, in increasing order of how much they give up:

1. **Map at the link address.** Exact, needs no inference, and needs a host
   that permits a low mapping -- `vm.mmap_min_addr=0` on Linux. Correct
   everywhere it works, and simply unavailable on Windows.
2. **Fold literal-pool pointers at lift time.** The lifter already knows the
   address of every `ldr rN, [pc, #k]` and can read the literal out of the
   image while lifting. If the value lands inside the image's vm range it is
   probably a pointer and can be emitted as `image_base + (v - link_base)`.
   This narrows the guess from "every word in `__DATA`" to "the words the code
   actually loads as constants", which is a far better place to guess -- but it
   is still a guess, and the range `0x1000`-`0x67000` is 4,096 to 421,888,
   which are entirely ordinary integers for a game to hold.
3. **Scan `__DATA` for pointer-shaped words.** The classic heuristic, and the
   worst of the three: the widest exposure to false positives and no
   information about how a word is used.

### What the measurement says

Taken, because it decides the design rather than merely informing it. Every
literal-pool load in Canabalt, classified by where its value points:

| literal value lands in | n | |
|---|---:|---:|
| `__DATA` | 5,054 | 86.3% |
| not an address at all | 723 | 12.4% |
| `__TEXT` | 76 | 1.3% |

And the functions line up exactly with the harness: of 152 self-contained
functions, **139 load an address-shaped literal and 13 do not** -- against 12
that pass the differential test today. The faulting functions are not a random
140; they are precisely the ones that load a pointer out of a literal pool.

So option (2) is *necessary*, and it is much less of a guess than it looked:
5,062 of the 5,130 address-shaped literals are `>= 0x10000`, too large to be a
plausible ordinary constant. Only 68 sites are genuinely ambiguous, and those
can be left unfolded and listed rather than guessed at.

But it is **not sufficient**, and the measurement is what shows why. Folding
literals fixes *reaching* `__DATA`. It does nothing for pointers stored
*inside* `__DATA` -- vtables, the ObjC class list, string tables -- which are
read at run time and are equally unrebased. Those need either a scan or the
fact that several of those structures have a documented layout, which is a
better lever than a heuristic and is the same one `objc_dump.py` already pulls.

The honest summary: **(1) is exact and costs a platform; (2) unblocks the
emitter's own verification and is 98.7% unambiguous; (3) is unavoidable for
pointers already in `__DATA` unless their structure is read rather than
guessed.** That is a decision about what iparecomp is willing to require of a
host, and it is not the emitter's to make.

## The emitter

### There is no decoder

The obvious first milestone was a decoder for armv6, armv7 and Thumb-2,
verified against capstone on real instructions. It was dropped before a line of
it was written, because capstone already decodes all three: the milestone was
to build a worse capstone and then test it against the real one.

`lifter.py` emits straight from capstone's operand detail -- registers, shift
kinds and amounts, memory bases and displacements, the condition field, the
write-back flag -- exactly as androidrecomp's lifter does. Everything genuinely
new about 32-bit ARM is *after* the decode, and that is where the effort went.

The one thing this costs is that capstone's own view has to be understood
rather than assumed. `lsl r0, r1, r2` comes back as two operands with the shift
folded onto the source, not three with the amount separate; `vmrs` has a
trailing `s` that is part of its name and not the flag-setting suffix. Both
were found by the coverage report rather than by reading, which is the argument
for having one.

### Where a function ends, and where the data starts

Function boundaries come from the symbol table, and a symbol-delimited function
includes the literal pool sitting at its end. A pool disassembles perfectly
into plausible nonsense -- a word of zeroes is `andeq r0, r0, r0`, which is why
that is the fourth most common mnemonic in Canabalt and `muleq` the thirteenth.

So the lifter walks reachability from the entry point and lifts only what it
reaches. A pool sits past an unconditional terminator with nothing branching
into it, so it is simply never reached, and no heuristic about what a word of
zeroes means is required. Without this, data is reported as missing emitter
coverage forever and the number never converges.

### The number to watch is functions, not instructions

A single unsupported instruction fails the whole function it sits in, so the
two move very differently and only the first decides whether a build is
possible. Canabalt went 80.8% -> 93.3% function completeness on one change that
moved instruction coverage 88.4% -> 99.5%; the last 6.7 points of *functions*
came from a form that was 0.5% of instructions but spread about one per
function. `--report` therefore ranks by functions broken, not by occurrences.

### One C function per guest function

As in androidrecomp. Guest pointers are host
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
is fortunate, because there is none. The independence is the whole point --
checking the emitters against capstone would prove nothing, since capstone is
where they get their operands.

Per-instruction is done: 5,985 cases over 159 operand forms, comparing
registers, flags, the vector file and memory, at 100% agreement. Whole
functions are next, and cover the control flow the first harness excludes by
construction.

Three details of the harness are load-bearing, and two of them cost a run to
learn:

**The image goes at the same address on both sides, and that address is not its
own.** These binaries are linked at 0x1000 and Windows will not map the first
64 KB, so the image cannot go where it was linked. That is exactly what
`image_base` is for: both sides are told the same slid base and every
PC-derived constant follows it.

**Reserve on the host's own granularity.** `VirtualAlloc` rounds a reservation
base *down* to the 64 KB allocation granularity and succeeds, so asking for a
one-page guard below a 64 KB-aligned address silently returns a region 60 KB
lower than requested. Every guest address then reads real data from the wrong
offset -- which looks exactly like an emitter bug, and cost an afternoon of
reading correct emitters. The harness now checks that the mapping landed where
it asked.

**The oracle gates the test.** The lifted side runs in-process, so it is never
handed a state Unicorn could not survive: if the oracle faults, the case is
dropped rather than being allowed to take the run down. What the oracle cannot
gate is a lifted instruction that computes a *different* address, which is the
bug being hunted -- so results are flushed per case and the last one written
names the instruction that faulted.

The first thing this harness found was not an emitter bug at all: seeding FPSCR
at random sets a rounding mode the generated C does not model, which shows up
as a one-ULP disagreement on int-to-float. The emitter assumes the default
rounding mode, which is what the ABI sets and what C's own conversions use.
That assumption is now written down instead of accidentally true.

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

## Calibrating the emitter

An emitter needs an oracle, and there are two kinds available here.

The general one is differential: run a lifted function and an emulated one on
the same inputs with the image at the same address, and compare registers,
flags and memory. That works for any target and is how the emitter will be
checked at scale.

The better one exists for exactly one game. Semi Secret Software released
[Canabalt for iOS](https://github.com/ericjohnson/canabalt-ios) in full,
including the MIT-licensed `flixel-ios` engine the class table here reveals —
`FlxGame`, `FlxSprite`, `FlxGLView`, `FlxState`. So for that binary there is
source-level ground truth: what a lifted function is *supposed* to compute can
be read, not merely compared against another black box.

That normally disqualifies a target — a game with public source does not need
recompiling. It is the reason to pick this one anyway. Bringing up a 32-bit
ARM emitter means being wrong in subtle ways about condition codes, shifter
carries and interworking, and a target where the intended semantics are
readable turns a week of bisecting into an afternoon. It is the calibration
weight, not the product.

Angry Birds is the first target chosen for its own sake: decrypted armv6, 3,633
functions, no source anywhere, and it has not run on a shipping device since
iOS 11.
