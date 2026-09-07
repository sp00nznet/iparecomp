# iparecomp

> A toolkit for turning old iOS apps' binaries into native desktop
> applications. Bring your own `.ipa`.

**Status: a lifted game is playable.** All 626 of
Canabalt's functions lift to C; 23,111 per-instruction cases over 191 operand
forms and 2,967 whole-function cases agree with Unicorn. The image maps at its
own link address with a zero slide, `objc_msgSend` dispatches into lifted code,
and the guest runs from `_start` through the whole launch into an SDL window
driving its own frame loop -- textures uploaded, text rasterised through
FreeType, the menu on screen the right way up, and a tap on a button running
that button's action -- and a tap on PLAY starts the game, which then runs:
the runner on the rooftops, the skyline scrolling behind, level generated as
it goes. What it still asks for is measured, not guessed: one run reports
**115 imports claimed and 32 still owed**. See [Milestones](#milestones).

**[Join the sp00nznet recomp Discord](https://discord.gg/CRpzGWZFcu)** — the
community hub for sp00nznet's recomp projects. Good place to ask questions,
show a port you are working on, or find out what people are stuck on before you
duplicate the effort.

### Recent changes

**Current version: v0.4.0 — _"Playable"_ (September 2026).**
See the [Changelog](#changelog) for what landed and when.

**New here?** [Getting started](docs/GETTING-STARTED.md) walks an `.ipa` all
the way to a window with the game drawing in it, one command at a time.

---

## What this is

The iPhone 3G era — iPhone OS 2.0 through 3.x, 2008 to 2010, when the App
Store first opened — produced a large catalogue of games that runs on nothing
today. The binaries are 32-bit ARM Mach-O, armv6 or armv7, and no current
device executes that natively. Apple dropped 32-bit support entirely in iOS 11.

That catalogue is the target, by static recompilation: replace the host,
satisfy the import surface, lift the machine code to C, and get an ordinary
native executable out — no emulator, no jailbreak, no device.

**This repository is deliberately app-agnostic.** A port supplies its own
bundle contract and links the library here. Nothing title-specific belongs in
this repo — that separation is much cheaper to keep than to retrofit.

The name is the file extension, not the platform. Nothing here uses Apple's
branding, trademarks, code, headers or SDKs.

## Licence and legal

**MIT** — see [LICENSE](LICENSE). Contributions must be your own work, under
the same terms.

**Tools only.** No app code, no assets, no extracted art, no publisher
binaries; `.gitignore` blocks all of it. You bring your own legally obtained
`.ipa`, and everything here operates on a file you already have. Nothing in
this repository contains or downloads any part of any application.

**Not affiliated with Apple.** iOS, iPhone, App Store and FairPlay are Apple
trademarks. No Apple code, headers, SDKs or branding is used or vendored here
— the framework surface is reimplemented from observable behaviour, and every
class and selector name is one the app already contains.

**No circumvention.** `ipa_probe.py` detects FairPlay encryption and stops.
There is no decryption here and none will be accepted.

**Why.** The 32-bit iOS catalogue stopped running on any shipping device at
iOS 11. This is preservation and education — how a Mach-O loads, how ARM lifts
to C, how dynamic dispatch is answered — aimed at software that runs nowhere.
If a rights holder wants it taken down, open an issue; it will be honoured in
good faith.

## Three things that make this harder than ARM64 Android

Worth knowing before writing a line, because each one shapes the design.

**1. `__TEXT` may be encrypted, and then nothing else matters.** App Store
binaries ship under FairPlay: an `LC_ENCRYPTION_INFO` load command with
`cryptid=1`, and the text section is ciphertext. No amount of shim work helps
— the lifter would be reading noise. This is triage gate one, and
`ipa_probe.py` checks it first and stops there:

```
## STOP -- `__TEXT` is FairPlay-encrypted

`LC_ENCRYPTION_INFO` cryptid=1, 1,228,800 bytes from 0x1000.
Nothing below this line is meaningful: the bytes the lifter would read
are ciphertext. A decrypted dump of the same binary is required.
```

**2. There are two instruction sets in one binary.** 32-bit ARM mixes ARM
(4-byte) and Thumb (2- and 4-byte) encodings, switched by `bx`/`blx` and
selected by the low bit of a target address. The encoding alone does not say
which a given byte is; decode Thumb as ARM and you get plausible-looking
garbage. ARM64 had no equivalent of this, and it is the single largest source
of new work.

Two things record which set a function is in, and both are exact rather than
inferred: the symbol table's `N_ARM_THUMB_DEF` bit, and — on binaries new
enough to have it — the low bit of each `LC_FUNCTION_STARTS` address. A
stripped binary with neither is the genuinely bad case; a stripped binary
*with* function starts is fine, which is most of the post-2011 catalogue.

**3. Most control flow is `objc_msgSend`.** An iOS app dispatches dynamically
by selector, and no static analysis resolves that. So it is not lifted at all
— it becomes a shim boundary. The ObjC half of the app is answered by a
runtime while the C/C++ half is compiled, which is what makes a game with a
few dozen classes and a few hundred selectors a far smaller job than its
framework list suggests.

There is also no easy path. An arm64 target can be run natively on an arm64
host, so its shim can be brought up and debugged before any lifting exists at
all. Nothing runs armv6, so iparecomp is a lifting project from day one.

## What you get

| Piece | What it does |
|---|---|
| `tools/ipa_probe.py` | Feasibility triage for a new title: encryption status, arch slices, function count and `__text` coverage, the ARM/Thumb split, the framework list, and Objective-C weight. Reads an `.ipa` directly. |
| `tools/ipa_host.cpp` | Loads a binary and prints the outstanding-import work list, grouped by the framework that owes each symbol. |
| `runtime/macho_image` | Parses a fat or thin Mach-O, picks an ARM slice, maps its segments, records the slide, and resolves every undefined symbol to the dylib that owes it. Refuses an encrypted image by name. |
| `runtime/arm32_context.h` | Guest CPU state and the operations lifted code emits — the emitter's target. Barrel shifter with its separate carry-out, unpacked flags, condition predicates, interworking helpers. |
| `tools/lifter.py` | Lifts armv6/armv7 and Thumb-2 to C, one C function per guest function. `--report` says what fraction of *functions* lift completely, which is the number that decides whether a build is possible. |
| `tools/lift_verify.py` | Differential-tests lifted instructions against Unicorn on encodings harvested from the real binary, with the image mapped at the same address on both sides. |
| `tools/lift_verify_fn.py` | Differential-tests whole lifted functions, including ones that call others, by neutralising the imports identically on both sides. 619 of Canabalt's 626. |
| `runtime/objc_runtime` | Realizes the class table out of `__DATA` and answers `objc_msgSend` by selector, dispatching into lifted code. Reports which selectors the binary sends that nothing in it implements -- the framework contract. |
| `tools/objc_verify.py` | Checks that runtime's realized table against `objc_dump.py`, which reads the same ABI independently. |
| `runtime/arc_boot` | Starts the guest and says where it stopped: the trap, a backtrace through lifted code, and the trail of calls out to the host. |
| `runtime/arc_mem` | The guest's heap and stack, below 4 GB, because a 32-bit guest cannot hold a host pointer. |
| `runtime/objc_host` | Framework classes as real class objects in guest memory, so the guest can hold them, send to them and inherit from them. |
| `runtime/shim_*` | The framework surface itself, one file per area: UIKit, Foundation and the ObjC object graph, CoreGraphics, OpenGLES, images, fonts, audio, libSystem. Each is a table of selectors and C symbols, so what is answered and what is not is a list you can read. |
| `runtime/window` | An SDL window with a compatibility GL context, the frame loop that stands in for `CADisplayLink` and `NSRunLoop`, the quarter turn from the guest's portrait framebuffer to a landscape window, and frame capture. |
| `tools/objc_dump.py` | Reads the Objective-C class table straight out of `__DATA` -- classes, methods, selectors, and each method's implementation address. An iOS host contract is a set of classes, and this is how you discover one. |
| `tools/conformance.py` | The emitter conformance suite: fixed encodings, **no `.ipa` required**, chosen to pin the semantics 32-bit ARM gets wrong quietly. The only check in this repo that runs on a clean checkout. |
| `tools/arc_selftest.c` | Checks the shifter carry and the flag helpers against real ARM semantics. The bugs it catches are silent ones. |

## Building

CMake 3.20+ and any C++17 compiler. zlib, SDL2, libpng and FreeType are each
optional, and each one that is missing removes only the piece it backs -- no
SDL2 is a run with no window, no FreeType is a run with no text.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

./build/arc_selftest                       # ARM semantics, no .ipa needed
./build/ipa_host path/to/Payload/Game.app/Game
```

On Windows add
`-DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake` so CMake
finds those four. A toolchain file only takes effect on a fresh cache,
so delete `build/` if you add it later.

Lift a binary and check the result against an emulator:

```sh
pip install capstone unicorn
python tools/lifter.py Game.ipa --report          # what still has no emitter
python tools/lifter.py Game.ipa --out generated/  # the lifted program
python tools/lift_verify.py Game.ipa              # against Unicorn
```

Run it, and see where it stops:

```sh
./build/ipa_host --run path/to/Game         # stop at the first missing piece
./build/ipa_host --permissive path/to/Game  # answer nil and list them all
./build/ipa_host --permissive --bundle=path/to/Game.app path/to/Game.app/Game
```

`--bundle` is what makes `pathForResource:ofType:` resolve, so a game only
loads its own art and fonts with it. Some of the PNGs in a shipped `.ipa` are
Apple's CgBI variant -- a private chunk and byte-swapped, premultiplied
channels -- and libpng refuses those with

```
libpng error: CgBI: unhandled critical chunk
```

It is a minority, and which files it hits decides whether it matters: 7 of
Canabalt's 73, all of them gameplay art, so the menu loads and draws from a
stock `.ipa` untouched. There is no de-cruncher here yet. Until there is, a
title that keeps its menu art in a CgBI file needs those converted first.

### Driving a run without a person at the keyboard

A frame loop is by construction a run that never finishes, and a question like
"does the menu draw" or "does PLAY start the game" should not need someone
watching a window. These are read from the environment:

| Knob | What it does |
|---|---|
| `ARC_MAX_FRAMES=n` | Stop the frame loop after `n` frames and report, instead of running until the window closes. |
| `ARC_TAP="x,y[,frame][;x,y,frame...]"` | Tap the window at those points, in window pixels, at those frames (200 by default): down, then up four frames later, because a button wants both halves. A list makes a walk through the menus repeat exactly. |
| `ARC_SHOT=<path>` | Write the last frame to `<path>` as a PPM, so "does it draw" has an answer that is not a trace. |
| `ARC_SHOT_EVERY=n` | With `ARC_SHOT`, write every `n`th frame instead, numbered `<path>.NNNN.ppm` -- a recording with no window chrome, no cursor, and the same frames every time. |
| `ARC_TRACE_CALLS=<substr>` | Print the host calls the guest makes whose name contains `<substr>`; `*` for all of them. |
| `ARC_TRACE_MSG=<substr>` | The same for Objective-C messages, matched on the selector, with the argument registers and what came back. |
| `ARC_TRACE_STACK=<words>` | Print that many words of the caller's frame alongside each traced message -- the arrays and counts a loop is working from, still addressable at the moment a bad value is passed. |
| `ARC_TRACE_DRAW` | Print the GL draw calls. |
| `ARC_TRACE_TEX` | Print texture uploads and the glyphs rasterised into them. |

Triage a new title before committing to it:

```sh
pip install capstone
python tools/ipa_probe.py Game.ipa --out triage.md
```

## Method

Point `ipa_probe.py` at an `.ipa`. The numbers that decide whether a port is
weeks or impossible, in the order they matter:

- **`cryptid`.** Nonzero and you are done; find a decrypted dump instead.
- **Percentage Thumb.** A binary that is entirely one instruction set is a
  dramatically easier first lift, because interworking never arises. Anything
  above zero means the emitter needs both decoders and the dispatcher must
  carry the mode bit.
- **`__text` coverage from the symbol table.** These binaries predate
  `LC_FUNCTION_STARTS`, so symbols are the only boundary evidence, and the
  uncovered remainder is literal pools mixed into the code. Expect 80–92%, not
  the 100% an NDK build's `.eh_frame` gives you.
- **Selector reference count.** How much of the app is dynamic dispatch that
  the ObjC runtime must answer rather than the lifter.
- **The framework list.** This is the shim surface, and it is the one place
  iOS is *kinder* than Android: every undefined symbol names the dylib that
  owes it, so the work list is exact rather than guessed from name prefixes.

Then `ipa_host` turns the remaining unknowns into a work list that shrinks.

## Measured on real binaries

Three iOS 3.x games, probed with the tools in this repo:

| | Canabalt | Angry Birds Rio | Cut the Rope |
|---|---|---|---|
| slice | armv6 | armv6 | armv6 + armv7 |
| `__TEXT` | decrypted | decrypted | **FairPlay, cryptid=1** |
| `__text` | 0.19 MB | 1.99 MB | — |
| functions | 626 | 3,633 | — |
| coverage | 80.1% | 91.1% | — |
| instructions | 37,185 | 494,331 | — |
| **Thumb** | **0%** | 21% | — |
| undefined symbols | 205 | 354 | 487 |
| frameworks | 14 | 14 | — |
| ObjC classes / selrefs | 49 / 506 | 38 / 866 | — |

A fourth, added because it is the opposite shape — modern, stripped, and mixed:

| | Flappy Bird 1.2 |
|---|---|
| slice | armv7 + armv7s |
| `__TEXT` | decrypted |
| `__text` | 0.75 MB |
| boundaries | `LC_FUNCTION_STARTS`, **3,169 functions, 100% coverage** |
| symbols | **1 defined** — fully stripped |
| **Thumb** | **39%** (1,231 Thumb, 1,938 ARM) |
| instructions | 201,776 |
| ObjC classes / selrefs | 134 / 1,804 |

This is the first target that exercises interworking, and the first where the
symbol table is no help at all.

Canabalt being 100% ARM is why it was picked as the first port: the emitter can
be built and validated with no interworking at all, and 626 functions is small
enough to lift in full and check against an emulator.

## Milestones

The reasoning behind each of these is in
[ARCHITECTURE.md](docs/ARCHITECTURE.md); this is the state.

- [x] **M0 — triage.** `ipa_probe.py`: encryption gate, slice selection,
      per-function ARM/Thumb disassembly, coverage, ObjC weight.
- [x] **M1 — loader.** Fat and thin Mach-O parsed, segments mapped, slide
      recorded, imports resolved to the framework that owes each one.
- [x] **M2 — the emitter's target.** `arm32_context.h`, with the shifter and
      flag semantics checked against hardware behaviour.
- [x] ~~**M3 — decoder.**~~ **Dropped, deliberately.** Capstone already decodes
      armv6, armv7 and Thumb-2, so this milestone amounted to building a worse
      capstone and then testing it against the real one. `lifter.py` emits from
      capstone's operand detail instead, which freed the whole effort for the
      emitter.
- [x] **M4 — emitter.** 626 of 626 functions, 41,167 of 41,167 instructions,
      compiling clean at `-Wall`. Condition codes as predicates, PC reads
      folded to constants at lift time, `ldm`/`pop` writing PC recognised as
      return or indirect branch, and the whole VFP surface these binaries use.
- [x] **M5 — differential test.** 23,111 per-instruction cases over 191 operand
      forms, and **619 of 626 whole functions** -- including every one that
      calls another, by neutralising the imports identically on both sides.
      100% agreement with Unicorn on registers, flags, the vector file and
      memory. The form count is the whole lesson, and it is worth reading why:
      [a shape that is never sampled is not tested](docs/ARCHITECTURE.md#why-62421-agreeing-cases-did-not-catch-it),
      however many cases run.
- [x] **M6 — the slide.** These binaries are non-PIE with an empty rebase
      table, so nothing records which words are pointers and the image cannot
      be slid at all -- but its link address sits below the 64 KB floor every
      desktop OS enforces. Solved exactly, with no heuristic: folding all 5,852
      literal-pool loads into constants leaves nothing reading `__TEXT,__text`,
      so every segment maps at its link address and the slide is zero. See
      [The slide has to be zero](docs/ARCHITECTURE.md#the-slide-has-to-be-zero).
- [x] **M7 — ObjC runtime.** 49 classes and their metaclasses realized from
      `__objc_classlist`, categories merged, and the superclass chain followed
      even where it leaves the binary. `objc_msgSend`, `objc_msgSendSuper2` and
      `objc_msgSend_stret` registered at their import stubs, so lifted code
      that sends a message dispatches into other lifted code. Checked two ways:
      against `objc_dump.py` on all 49 classes and 518 method pairs, and 88/88
      real messages arriving at the implementation the table names.
- [x] **M8 — framework shims.** The whole launch path, and each piece was named
      by the run that stopped on it rather than guessed in advance: a guest
      heap and stack below 4 GB, libSystem, framework classes as real class
      objects in guest memory, Foundation, CoreGraphics geometry written out
      exactly, OpenGLES on desktop GL, the bundle's PNGs through libpng, fonts
      through FreeType, and audio that fails honestly rather than plausibly so
      the game takes its own no-sound path. **115 imports claimed, 32 still
      owed.**
- [x] **M9 — a window.** 480x320 with a compatibility GL context, a frame loop
      standing in for `CADisplayLink` and `NSRunLoop`, and the guest's portrait
      framebuffer turned upright in clip space -- one matrix rather than a
      second pass. At 300 frames the menu is complete and the frame is 100% not
      black: the logo, the skyline, the billboard, and the ABOUT and PLAY
      buttons, either of which runs its action when tapped.
- [x] **M10 — the game itself.** PLAY starts it, and it runs: `PlayState`
      builds, the runner is on the rooftops, the skyline scrolls, and the
      level is generated as it goes. What stood in the way was one switch --
      `ldrls pc, [pc, r3, lsl #2]` in `-[Shard init]`, whose case bodies the
      reachability walk could not see, leaving 540 of the function's 807
      instructions unlifted. Tables are resolved at lift time now, from
      read-only `__TEXT` on an unslid image, with the bound taken from the
      guest's own `cmp`.
- [ ] **M11 — the rest of it.** Audio that actually plays, the 32 imports
      still owed, the 7 CgBI-crushed PNGs that libpng refuses (`block`,
      `slope`, `hud`, `gameover` -- the gameplay set), and Thumb-2 for the
      titles that are not this one.

## Changelog

### v0.4.0 — _"Playable"_ (September 2026)

Canabalt plays. Tap PLAY and the runner runs.

- **The lifter follows a jump table.** `ldrls pc, [pc, rN, lsl #2]` is a dense
  switch, and the reachability walk stopped dead at it: the table is data, so
  nothing branched to the case bodies and they lifted to nothing. Resolved
  exactly -- the table is in read-only `__TEXT` on an unslid image, so it is
  read at lift time like any literal, and the bound comes from the `cmp` that
  set the condition. **540 of the 807 instructions in `-[Shard init]` were
  invisible**, which is the function `PlayState` builds its shards in.
- That is also a correction to what "626 of 626 functions complete" meant: it
  was complete over everything the walk could *reach*, and the walk could not
  reach through a switch.
- The touch transform records why it is what it is. The guest does its own
  quarter turn in `-[FlxGlobal touchPoint]`, so the host undoes only the
  window's landscape orientation.

### v0.3.0 — _"Stripped"_ (September 2026)

A binary with one symbol in it now lifts, which opens the post-2011 catalogue.

- **`LC_FUNCTION_STARTS` is a boundary source**, not just a number in the
  triage report. Whichever of it and the symbol table accounts for more of
  `__text` wins. The low bit of each start address gives the ARM/Thumb mode
  exactly, the same convention `N_ARM_THUMB_DEF` uses — so a stripped binary's
  mode is read, not inferred.
- **The starts table was being read from the wrong base.** The deltas
  accumulate from the Mach-O header — `__TEXT` — and the code took
  `segments[0]`, which is `__PAGEZERO` at address 0. Every function came out
  one `__TEXT` vmaddr too low. Never noticed, because nothing had consumed it.
- **`movw` and `movt`.** A 32-bit constant with no literal pool to load it
  from is a `movw`/`movt` pair, and `movt` is the only move that reads its own
  destination. `movw` alone was blocking 2,692 of Flappy Bird's 3,169
  functions.
- The triage report now names which source the boundaries came from, because
  "3,169 functions from the symbol table" was a lie on a binary with one
  symbol in it.
- Measured on *Flappy Bird 1.2* — stripped, armv7/armv7s, 39% Thumb: **0 → 
  3,169 functions**, 100% of `__text` covered, and lifting goes from 11.0% to
  **79.9% of functions and 99.2% of instructions**. What remains is Thumb-2:
  IT blocks, `cbz`/`cbnz`, `tbb`, `strd`/`ldrd`, NEON.
- Canabalt is unchanged throughout: 626/626, 4,044/4,044 per instruction,
  857/857 over 144 whole functions, and a byte-identical rendered frame.

### v0.2.0 — _"Conformance"_ (September 2026)

A suite that runs without a game, and the two emitter bugs it found on its
first run.

- **`tools/conformance.py`** — 45 hand-written encodings through the same
  differential harness `lift_verify.py` uses, so a pass means the same thing.
  Every other check in this repository needs a binary you supplied; this one
  runs on a clean checkout, which is what makes an emitter change reviewable
  by someone who does not own a suitable game.
- **`adcs`/`sbcs`/`rscs` used the wrong carry.** The flag helper *writes*
  `c->cf`, and the result expression read it back afterwards — so the sum used
  the carry the instruction had just produced instead of the one it was given.
  Wrong by exactly one, and only with `S` set.
- **`adc`/`sbc`/`rsc` clobbered the flags** with `S` clear. capstone reports
  `update_flags` for those three because they *read* the carry, so the field
  means "touches CPSR" rather than "writes it", and the emitter believed it.
- Neither bug was reachable from the existing tests: **Canabalt contains no
  `adc`, `sbc` or `rsc` at all**, so no amount of harvesting from that binary
  would ever have sampled them. That is the argument for the suite.
- [Getting started](docs/GETTING-STARTED.md) — an `.ipa` to a drawing window,
  one command at a time.

### v0.1.0 — _"First Light"_ (September 2026)

First tagged version, cut at the point the toolkit stopped being a lifter and
started being a host: a lifted armv6 game reaches its own frame loop and draws
its menu, and a tap on a button runs that button's action.

- **The emitter is done and checked.** 626 of 626 functions, 41,167 of 41,167
  instructions, verified against Unicorn per instruction and per whole
  function.
- **The image loads where it has to.** Zero slide, no heuristic, no patched
  host.
- **The ObjC runtime answers `objc_msgSend`** out of the binary's own class
  table, and lifted code dispatches into lifted code.
- **115 of 147 imports answered**, across UIKit, Foundation, CoreGraphics,
  OpenGLES, images, fonts and audio.
- **A run can record itself** -- `ARC_TAP` scripts the taps and
  `ARC_SHOT_EVERY` writes the frames, so a walk through the menus repeats
  exactly.

## Ports

- [canabaltrecomp](https://github.com/sp00nznet/canabaltrecomp) — Canabalt
  (Semi Secret Software, 2009). 626 functions, no interworking, 14 frameworks.
  Chosen as the **emitter's calibration target**: Semi Secret open-sourced the
  game in full, so the original armv6 binary and the source it was built from
  are both available. Lifted output can be checked against ground truth, which
  is not normally possible.

Angry Birds (armv6, decrypted, 3,633 functions, 21% Thumb) is the first real
preservation port, once the emitter handles interworking.
