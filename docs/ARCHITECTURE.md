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

The sharpest constraint in the project, and the one that decided how the loader
works. It was found by the whole-function harness rather than by reading.

Canabalt's binary is `MH_EXECUTE`, **not** `MH_PIE`, and it carries no
relocation information at all:

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

This is not a Canabalt quirk. Every armv6 title measured is the same -- Angry
Birds Rio and Angry Birds Halloween do not carry `LC_DYLD_INFO` at all -- so no
choice of target avoids it:

| | slice | PIE | rebase | local relocs |
|---|---|---|---|---|
| Canabalt | armv6 | no | 0 | 0 |
| Angry Birds Rio | armv6 | no | absent | 0 |
| Angry Birds Halloween | armv6 | no | absent | 0 |

So a pointer in `__DATA`, or one sitting in a literal pool in `__TEXT`, is a
bare link-time address like `0x00041a9c` with nothing marking it as one. An
image mapped anywhere else cannot be corrected, because there is no list of
what to correct. **The image has to be mapped at its own link address, and the
slide has to be zero.**

`__TEXT` begins at `0x1000`, and no desktop OS will hand that out: Windows
reserves the first 64 KB as the null-pointer partition, and Linux's
`vm.mmap_min_addr` defaults to the same. For a while that looked like a choice
between requiring a patched host, guessing which words are pointers, or
scanning `__DATA` for pointer-shaped words -- all three bad.

### The way out

It came from separating two things that had been treated as one:

- **Folding a literal-pool *load* into a constant is exact.** `__TEXT` is
  mapped r-x and no instruction in the image can write it, so the value at that
  address is fixed at link time and the emitter can simply read it while
  lifting. `ldr r0, [pc, #8]` becomes `ARC_W(c, 0, 0x41a9c)`.
- **Adding the slide to that *value* is a guess.** Nothing says whether
  `0x41a9c` is a pointer or an integer.

Only the first is needed, and it makes the second unnecessary. Look at where
the sections actually sit:

| section | range | below the 64 KB floor? |
|---|---|---|
| `__TEXT,__text` | `0x2504`-`0x2fa30` | **yes, and only this one** |
| `__TEXT,__cstring` | `0x2fa30`-`0x36158` | no |
| `__TEXT,__const` | `0x36158`-`0x3a306` | no |
| everything in `__DATA` | `0x3b000`-`0x4367c` | no |

`__text` is the only section under `0x10000`, and it holds exactly two kinds of
byte: instructions, which are never executed because the lifted C is executed
instead, and literal pools, whose only readers are the loads just folded away.
5,852 of Canabalt's 5,853 literal-pool loads fold.

So nothing needs to be mapped below `0x10000`. The loader maps every segment at
its link address from the floor upward, the slide is zero, and every absolute
pointer in the file is correct because it was never moved. The OS's own refusal
to map the first 64 KB becomes the low guard page for free: anything that does
still read down there faults immediately instead of quietly reading a zero.

```
link base  00001000, span 0.4 MB
slide      00000000
           __TEXT       00001000 +0x3a000  host 0000000000010000
           __DATA       0003B000 +0x9000   host 000000000003b000
           __LINKEDIT   00044000 +0x22970  host 0000000000044000
```

The measured effect on verification is the whole point: whole-function
differential testing went from **12 of 152** self-contained functions to
**150 of 152**, at 100% agreement. The 140 that used to fail were not
mis-lifted. They were reading globals through pointers the harness had moved.

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

### How lifted code reaches the runtime at all

Three pieces had to exist before a message could be sent, and each was missing
for a different reason.

**A stub address is the name of an import.** Lifted code calls `objc_msgSend`
by branching to its stub in `__TEXT,__symbolstub1`, which is outside `__text`
and therefore never lifted. Turning that address back into a symbol does not
need the bind opcodes: a stub section carries its first index into the indirect
symbol table and its stride, so entry *i* is indirect symbol `reserved1 + i`.
That resolves 123 stubs and 147 pointer slots in Canabalt, `_objc_msgSend`
among them.

**A generated stub must consult the native table, not trap.** The lifter emits
a body for every branch target it did not lift, and emitting `arc_trap` there
unconditionally makes every import unreachable by construction. They go through
`arc_dispatch_miss` instead, which is where registered natives are found.

**"Resolved" is not "is a host function".** On the Android side an import
resolves to a real host address because the library is loaded natively. Here it
does not: a guest address is 32 bits and a host function is not, so casting one
to the other cannot work. `arc_register_native` now takes the host function
alongside the guest address it answers to.

### Where the class graph leaves the binary

A class that inherits from `NSObject` has a **zero** in its superclass field.
Not a root class -- a field dyld was going to fill in, with a bind entry
pointing at it saying `_OBJC_CLASS_$_NSObject`. So the class graph does not say
where it ends until the bind opcodes are interpreted, which is a small stack
machine over `LC_DYLD_INFO`.

Canabalt has 848 bindings, 281 of them landing inside `__objc_data` -- the
class structures themselves. Reading them turns "this superclass is external"
into "this superclass is `UIView`", which is the difference between a trap that
says something is missing and one that says what to write:

```
objc_msgSend: +FlxGame does not respond to alloc, owed by NSObject
```

### What the runtime is asked for, exactly

Of 506 selectors the binary references, **314 are implemented by its own
classes** and answered by lifted code; 192 are not implemented anywhere in the
image and must come from a framework. Which receiver a given send has is not a
static fact -- that is the entire reason `objc_msgSend` is a shim boundary
rather than something to lift -- so this cannot say which class owes which
selector. What it can say exactly is which selectors have no implementation at
all, and that is the contract.

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

## Running it

### A 32-bit guest cannot hold a host pointer

This has no equivalent on the Android side, where guest and host are both
64-bit, and it is not something a shim can paper over. Forward `malloc` to the
host's `malloc` and it compiles, links, runs, and hands the guest the bottom
half of a 64-bit address. Nothing fails at the call: a plausible pointer comes
back and faults much later, somewhere unrelated.

So the guest gets its own heap and stack, reserved low enough to be
addressable in 32 bits, and every shim that returns a pointer allocates from
there. It is a bump allocator and `free` does nothing -- sized against the
machine the game shipped on, which had 128 MB of RAM in total, so half a
gigabyte that is never reclaimed is far more than the game can have been
written to need, and exhausting it is loud rather than silent.

### An empty class reference is worse than a missing one

`main` begins `[[NSAutoreleasePool alloc] init]`. With nothing bound into
`__objc_classrefs` the guest loads zero, sends to nil, and gets zero back --
and a message to nil is not an error in Objective-C, it is an answer. So the
pool is silently not created and nothing complains.

That is why framework classes are *objects in guest memory* rather than a
host-side table. `NSObject` has a real class_t and class_ro_t at a real guest
address, laid out exactly as the ABI defines, so the same reader walks host and
guest classes alike and the 220 bind sites dyld would have filled can be filled
with something. What differs is only where the implementation lives: a guest
class's method list points at lifted code, a host class's methods are C
functions held beside the class object.

### One run should name the whole contract

`--run` stops at the first thing that is missing, which is right when fixing
one. `--permissive` answers an unimplemented framework message with nil,
records it, and carries on -- and because nil is a legitimate answer, most of
the startup path survives it. One run then enumerates what the whole path
needs rather than one rebuild per selector.

On Canabalt that is twelve messages, and they carry it eight frames into its
own code:

```
  0x0000672c  -[FlxGame initWithState:orientation:backgroundColor:]
  0x000064ac  -[FlxGame initWithState:orientation:]
  0x000043bc  -[FlxGlobal init]
  0x000041ac  +[FlxGlobal sharedFlxGlobal]
  0x0000317c  -[CanabaltAppDelegate preloadSounds]
  0x00003460  -[CanabaltAppDelegate applicationDidFinishLaunching:]
  0x00002550  _main
  0x00002504  start
```

That backtrace is the reason the lifter emits a frame note per function under
`ARC_FRAMES`. A fault in lifted code names an address in the data it touched
and never the code that touched it, and the host stack is 626 identically
shaped C functions; without the ring there is nothing to read.

### Three ways an import is reached, and all of them have to work

Getting the launch path to run end to end came down to this, and each part
failed differently.

**A `bl` goes to the stub.** That was wired first and it is the obvious one.

**A PIC call loads a pointer slot and branches to what it holds.** Nothing
filled those, so they held zero. What goes in is the *stub's own address*, not
the shim: a guest address is 32 bits and a host function pointer is not, so the
slot can never hold the implementation. Branching to the stub arrives at the
same native table the direct call uses.

**And an import can have more than one slot.** A lazy one and a non-lazy one,
reached by different code. Recording only the first left the other at zero.

**Some imports have no stub at all.** `exit` is only ever reached through its
pointer, so the linker emitted no code for it anywhere -- and with no address
to register a shim against, it stayed unreachable. Each of those gets an
invented address in the guest heap, which gives every import one identity that
a shim, the native table and a pointer slot can all agree on.

The symptom of the last two was the same and it was a good one: the guest ran
`main` to completion, returned, and then branched to nothing. `_start` calls
`main` and tail-calls `exit`.

### `[super init]` leaves the binary

Almost every class here inherits `NSObject` directly, so `[super init]` --
which is in every one of them -- immediately asks for a class the binary does
not contain. `objc_msgSendSuper2` reads the superclass out of the class it was
given, finds zero, and without help sends the message to nothing.

Zero is not "no superclass". It is the same unbound field the class graph has
everywhere else, and the bind table names it. Crossing to the host class object
there is what took the run from stopping in `-[FlxGlobal init]` to finishing.

### OpenGL ES is the reason to recompile rather than emulate

Every OpenGL ES 1.1 entry point Canabalt uses is also OpenGL 1.1, under the
same name with the same semantics. The shims are therefore calls, not
translations, and the system library resolves all of them with no loader and no
extensions -- `glOrthof` taking floats where desktop GL takes doubles is the
only difference in thirty-eight functions.

That is worth stating plainly because it inverts the usual comparison. An
emulator for this era has to implement the PowerVR MBX, which is undocumented,
tile-based, and the hardest single piece of the machine. A recompiler replaces
the *call* instead of the chip, and the call is free. The framebuffer object
is not even created: the guest asks for one, gets a plausible name, and its
drawing lands in the window directly.

### Answer honestly, not plausibly

Audio is not implemented, and there are two ways to say so. `AudioSession` is
told everything worked, because nothing depends on it. Opening a *file* is told
it failed -- with the error code the real framework returns, so a caller
matching on it behaves as it would.

The first attempt reported success with a zero length, and the game allocated a
buffer from a size it had never been given: a quarter of a gigabyte out of the
guest heap in one call. A refusal the game already handles beats a success it
cannot, and the game's own log says so:

```
[guest] Error opening file (bomb_explode.caf): 2003334207
```

### An empty class reference, again

`___CFConstantStringClassReference` is one bind symbol that every `@"..."` in
the binary points its isa at. Skipping it left every string literal in the
program with a null class, so `copy` or `UTF8String` sent to one went nowhere
-- the same failure as the empty `__objc_classrefs` slot and just as quiet.
Binding it took the count of filled class references from 220 to 504.

### The hierarchy has to exist before anything names it

Host classes are created on first mention and never re-parented, so whichever
call happens first decides the superclass. A shim table mentioning UIImageView
in passing rooted it at NSObject and cut it off from everything UIView owns,
which showed up as `-[UIImageView setAlpha:]` not being found while UIView
plainly had it.

### What a permissive run cannot do

Answering nil and carrying on works because nil is a legitimate answer -- but
a loop whose exit condition depends on the answer will not terminate if the
answer is always nil. A measuring run that never ends measures nothing, so
there is a budget on it, and reaching that budget is reported as what it is.

### A stub that hangs is worse than one that is wrong

Font metrics are the clearest case of it. `CGFontGetGlyphAdvances` has to write
an advance per glyph, and a plausible-looking half-em was the obvious stand-in.
It hung the game: `-[SSText(Private) nextWrapOffsetForGlyphs:]` word-wraps by
asking how many glyphs fit in the line, could not fit even one, and never moved
the offset.

Zero advances terminate -- everything fits, the loop ends on its first pass,
and the text is invisible, which it is anyway without a rasteriser. That is
still not enough, because the layout above it loops on the font's own size, and
the honest conclusion is that text needs FreeType rather than a better guess.

The general rule this produced: when a shim's return value feeds a loop's exit
condition, the safe stub is the one that ends the loop, not the one that looks
most like a real answer.

### A run that does not finish reports nothing

Which is why every lifted function entry counts against a budget. Exhausting it
traps, so the frame ring survives and names what was going round -- and the
frame loop resets it, because a running game is supposed to enter functions
forever. The budget is about *reaching* the loop, not about staying in it.

It paid for itself immediately:

```
stopped: the guest entered its function budget without reaching the frame loop
  0x00020fc8  -[SSText padding]
  0x00020abc  -[SSFont size]
  0x00021824  -[SSText(Private) nextWrapOffsetForGlyphs:]
```

### A table that fills up quietly

`objc_msgSend` reported itself unimplemented while every one of the binary's
own classes still loaded correctly -- a symptom pointing nowhere near its
cause. The context-native table held 64 entries, the GL shims alone are 35, and
once it was full every later registration silently did nothing.

The fix is the size, but the lesson is the silence: a capacity limit that is
reached without saying so converts an ordinary mistake into an unrelated
mystery. It is loud now.

### Where an aggregate is returned is the ABI's decision

`-rangeOfCharacterFromSet:options:range:` returns an `NSRange`: two words,
small enough to look like it comes back in a register pair. It does not. The
Objective-C ABI sends it through `objc_msgSend_stret`, and under stret the
hidden return pointer takes r0 and everything shifts up -- receiver r1,
selector r2, first argument r3.

Reading it as an ordinary send takes the *string* for a return buffer and the
selector for the string, which had the word-wrap loop searching a nonexistent
string forever. A `CGPoint` from `-center` does the same thing, and it is two
floats.

There is no size rule to reason from here. The reliable way to tell is the call
trail, which now records whether a message arrived through `objc_msgSend` or
`objc_msgSend_stret`:

```
  -[SSText center]
  objc_msgSend_stret
```

### A fault has to describe itself

A trap is the lift saying it cannot express something, and it prints a trail. A
*fault* is the guest touching memory that is not there, and by default it
prints nothing -- the host stack is thousands of identically shaped C
functions and the faulting address names the data rather than the code.

So a handler reports the address, asks the OS what is at it, and prints the
same trail:

```
the guest faulted: reading 0000000080200593
  0000000080200593 is free

guest functions entered, most recent first:
  0x00021300  -[SSText setText:]
  0x00021fac  -[SSText(Private) computeNewBounds]
```

"Free" is the whole diagnosis: a committed region touched the wrong way is a
different bug from an address that was never anything. And it has to be a
*vectored* handler rather than an unhandled-exception filter, because the C
runtime installs its own SEH chain and the filter never runs.

### Refuse a bad value where it is used

The text path faulted reading `0x80200593`, and a faulting address on its own
only says which byte was touched. Three things in order turned that into a
sentence.

The fault handler prints the guest's registers, so the value can be found in
them rather than inferred -- it was in r0, r2 and r6, with a selector in r1,
which is the shape of a message about to be sent.

The runtime then refuses a receiver that is not somewhere the guest could have
got a pointer: not the image, not the heap, not the stack. That converts a
segfault into

```
stopped: objc_msgSend: 0x80200593 is not an object, and it was sent copy
```

with the frame ring still pointing at `-[SSText setText:]`. The check has to
come *before* the isa is read, and the first version of it did not, because the
caller computed the isa in the argument list.

And where an aggregate is returned is now checked rather than assumed. A
shim returning a `CGRect` writes through a hidden pointer that only exists
under `objc_msgSend_stret`; reached through the ordinary send it would write
sixteen bytes over the receiver's own header and produce exactly this kind of
garbage pointer somewhere else. The runtime records which of the two a send
came through and those shims refuse the wrong one. It did not fire here, which
is itself the useful result: that whole class of bug is ruled out rather than
suspected.

### A ring of entries is not a call chain

The frame ring said which functions ran, and for a while that was enough. It
stopped being enough as soon as the question was "who passed this value",
because siblings in a ring look exactly like a parent and a child.

The fix is small now that the runtime knows the live context: the note is
emitted at the top of a lifted function, before its prologue saves anything, so
`lr` still holds the return address. Recording it turns a ring of entries into
a ring of call *edges*:

```
  0x00021300  -[SSText setText:]  <- 0x00023bfc -[FlxText initWithFrame:text:color:font:size:align:angle:]
  0x00023b04  -[FlxText initWithFrame:...]  <- 0x00023010 +[FlxText textWithFrame:...]
  0x00022f94  +[FlxText textWithFrame:...]  <- 0x000230a8 +[FlxText textWithFrame:text:color:font:size:align:]
```

That is the difference between "something passed a bad string" and a named
chain of four convenience factories, each forwarding a longer stack argument
list than the last.

### Testing a caller means stubbing its callees on both sides

The harness used to test only *self-contained* functions -- no calls at all,
because a call would run arbitrarily deep and reach an unlifted stub. That was
150 of Canabalt's 626, and it left every argument forwarder, initialiser and
wrapper untested: exactly the shape where a lifting bug survives.

The first attempt at widening it was to allow calls whose whole tree is
lifted. That added **nothing**. Every non-leaf function in an Objective-C
binary sends a message, so its call tree always reaches `objc_msgSend`, and
`objc_msgSend` is an import.

What works is to neutralise the imports identically on both sides: reaching one
sets r0 to zero and returns, on the lifted side through a registered native and
in the oracle through a code hook over the stub range. What the callee would
have done does not matter; that the two sides do the same thing does. That took
the harness from **152 functions to 619 of 626**, and all of them agree.

The result is worth more than the number. The bug being chased at the time ran
through four `+[FlxText textWithFrame:...]` forwarders and a seven-argument
initialiser, all of which are now covered and all of which pass -- so the
lifter is not where the bad value comes from, and the search moved to the
runtime. A harness that cannot reach the code under suspicion cannot exonerate
it either.

### Tracing messages, not just calls

`ARC_TRACE_CALLS` prints the host calls a guest makes; `ARC_TRACE_MSG` does the
same for Objective-C messages, matched on a substring of the selector, with the
argument registers and the first stack words:

```
[msg] +[FlxText textWithFrame:text:color:font:size:] r2=0x43c40000 r3=0x44080000
      sp0=0x43720000 sp1=0x41800000 sp2=0x80200593
```

It prints what came back as well, because a shim returning something
implausible is the likeliest origin of a bad pointer and only the return value
shows it:

```
[ret] localizedStringForKey:value:table: -> 0x20010700
[ret] CGColor -> 0
```

A name in the trail says a message was sent. The arguments say whether what it
carried made sense, and the returns say where a value came from -- which is the
difference between watching one arrive wrong and knowing what produced it.

On the text bug that chain of traces established, in order: the bad value is
already wrong at the top of the forwarding chain; it is passed by no earlier
message; it is returned by no message at all; and it is not a constant anywhere
in the image. What is left is memory -- and the instruction that loads it is
`ldr r5, [r3, r6, lsl #2]` in `-[MenuState init]`, indexing an array of menu
labels whose third slot was never written. The loop's bound comes from a
message return two instructions earlier, and the labels come from
`-[NSBundle localizedStringForKey:value:table:]`, which correctly returns the
key: the bundle's only `.strings` file belongs to the Settings preferences, not
to the menu.

`ARC_TRACE_STACK=<words>` prints the caller's frame alongside the message,
which is possible because a message is sent from *inside* that frame -- so the
arrays and counts a loop is working from are still addressable at exactly the
moment the bad value is passed. On this bug it shows an array of four valid
string pointers at `sp+0x120`, and the bad value appearing nowhere in the frame
except the outgoing argument slots.

Which means the value is not sitting in the frame waiting to be read: it is
produced between the load and the call. That is the next thing to look at, and
it is a much smaller window than "somewhere in text layout" was.

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
