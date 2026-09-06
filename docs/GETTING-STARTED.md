# Getting started

You have an `.ipa`. This walks it to a window with the game drawing in it, one
command at a time.

Every command and every block of output below is from a real run against
*Canabalt* 1.0. Your numbers will differ; the shapes will not.

- [What you need](#what-you-need)
- [1. Triage: is this title possible at all?](#1-triage-is-this-title-possible-at-all)
- [2. Read the verdict](#2-read-the-verdict)
- [3. Lift it](#3-lift-it)
- [4. Check the lift against an emulator](#4-check-the-lift-against-an-emulator)
- [5. Scaffold a port](#5-scaffold-a-port)
- [6. Build](#6-build)
- [7. Run it](#7-run-it)
- [8. See it draw](#8-see-it-draw)
- [When it stops somewhere new](#when-it-stops-somewhere-new)

---

## What you need

- **Python 3.9+** with `capstone` (triage and lifting) and `unicorn`
  (verification): `pip install capstone unicorn`
- **CMake 3.20+** and a C++17 compiler
- **SDL2, libpng, FreeType, zlib** — all optional, and each one that is missing
  removes only the piece it backs. No SDL2 is a run with no window; no FreeType
  is a run with no text.
- **An `.ipa` you legally own.** Nothing in this repository ships app code or
  app assets, and nothing here will fetch any.

The tools read the `.ipa` directly. You do not need to unzip it first, except
for step 7, which wants the `.app` directory so the game can find its own
resources.

## 1. Triage: is this title possible at all?

Always do this first. It costs a second and it can save you a month.

```sh
python tools/ipa_probe.py "Canabalt.ipa"
```

```
# Triage: `Canabalt`

- bundle: `com.semisecretsoftware.Canabalt` 1.0
- slices: 1 (armv6)
- analysed: **armv6**, min iPhone OS unstated
- `__TEXT`: **not encrypted** (`LC_ENCRYPTION_INFO` present, cryptid=0)
- `__text`: 0.19 MB @ 0x2504
- `LC_FUNCTION_STARTS`: **absent** -- function boundaries must be
  recovered from the symbol table and by following calls
- symbols: 1,074 defined, 206 undefined
- functions from the symbol table: **626** covering 80.1% of `__text`
- instruction sets: **626 ARM, 0 Thumb** (0% Thumb)
- instructions: 37,185 (216 distinct mnemonics)
```

Add `--out triage.md` to keep it, and `--slice armv7` to look at a different
slice of a fat binary.

## 2. Read the verdict

Four numbers decide whether this is weeks or impossible. In the order they
matter:

**`cryptid`.** Nonzero and you are done. The `__TEXT` section is FairPlay
ciphertext and the lifter would be reading noise. The probe stops there and
says so rather than producing a report about nothing:

```
## STOP -- `__TEXT` is FairPlay-encrypted

`LC_ENCRYPTION_INFO` cryptid=1, 1,228,800 bytes from 0x1000.
Nothing below this line is meaningful: the bytes the lifter would read
are ciphertext. A decrypted dump of the same binary is required.
```

**Functions, and where they came from.** `626 covering 80.1%` is a good
result. These armv6-era binaries predate `LC_FUNCTION_STARTS`, so the symbol
table is the only boundary evidence and 80–92% coverage is normal — the
remainder is literal pools mixed into the code, not missing functions.

A **stripped** binary is the bad case, and it looks like this:

```
- functions from `LC_FUNCTION_STARTS`: **3,169**
- symbols: 1 defined, 457 undefined
- functions from the symbol table: **0** covering 0.0% of `__text`
- instructions: 0 (0 distinct mnemonics)
```

Boundaries exist here — 3,169 of them — but no symbol survives to say which
instruction set each function is in, and the analysis is symbol-driven today.
See [Known limits](#known-limits).

**Percentage Thumb.** A binary that is entirely one instruction set is a
dramatically easier first lift, because interworking never arises. `0% Thumb`
is why Canabalt was the calibration target.

**Selector references.** How much of the app is dynamic dispatch that the ObjC
runtime answers rather than the lifter. Canabalt's 506 is small; 1,800 is a
much larger runtime surface.

## 3. Lift it

Ask what fraction lifts before asking for output. The number that decides
whether a build is possible is *functions*, not instructions — one unlifted
instruction breaks its whole function.

```sh
python tools/lifter.py "Canabalt.ipa" --report
```

```
Canabalt: 626 functions, __text 0.19 MB @ 0x2504, link base 0x1000

functions complete : 626 / 626  (100.0%)
instructions lifted: 41,167 / 41,167  (100.0%)
literals folded    : 5,852  (reads of __TEXT resolved at lift time, so none remain at run time)
```

Then write the program out:

```sh
python tools/lifter.py "Canabalt.ipa" --out generated/
```

```
wrote generated/: 626 functions, 123 stubs across 8 units (4.1 MB)
```

Both take under a second. Eight translation units because one 4 MB C file is a
slow compile and a worse incremental one; `--shards` changes the count.

**This output is machine code derived from your binary. Do not commit it.**
Add `generated/` to your `.gitignore` before you forget.

## 4. Check the lift against an emulator

The emitter is not trusted because it looks right. Start with the suite that
needs no binary at all — if this fails, nothing below it is worth running:

```sh
python tools/conformance.py
```

```
conformance: 45 encodings, 24 states each

agreed: 952 / 952  (100.00%)
```

Then check it against Unicorn on encodings harvested from *your* binary, with
the image mapped at the same address on both sides.

```sh
python tools/lift_verify.py "Canabalt.ipa"
```

```
Canabalt: 766 encodings over 191 forms, 6 states each

agreed: 4,044 / 4,044  (100.00%)
```

`--per-form` and `--seeds` turn the sweep up; the figure quoted in the README
(23,111 cases over those same 191 forms) is a deeper run than this default.

Whole functions, including the ones that call other functions, by neutralising
the imports identically on both sides:

```sh
python tools/lift_verify_fn.py "Canabalt.ipa" --generated generated/
```

```
  619 testable of 626: 152 call nothing, 467 have a fully lifted call tree
Canabalt: testing 150 functions, 6 states each

agreed: 857 / 857  (100.00%)   over 144 functions
```

If either disagrees, stop. A disagreement is an emitter bug, and it will not
get easier to find after ten thousand lines of shim work sit on top of it.

> These shell out to a C compiler, `gcc` by default. Set `CC` if yours is
> called something else.

## 5. Scaffold a port

**iparecomp is deliberately app-agnostic.** The loader, the shims, the ObjC
runtime and the emitter are title-agnostic and live here; the lifted program
and anything title-specific lives in a repo of yours that links this one.

That repo is very small. A whole port scaffold:

```
myport/
├── iparecomp/          # this repo, as a submodule
├── generated/          # the lifted program -- built locally, never committed
├── .gitignore
└── CMakeLists.txt
```

```sh
mkdir myport && cd myport && git init
git submodule add https://github.com/sp00nznet/iparecomp.git iparecomp
printf 'generated/\nbuild/\n*.ipa\nPayload/\n*.app/\n' > .gitignore
```

`CMakeLists.txt`, in full:

```cmake
cmake_minimum_required(VERSION 3.20)
project(myport C CXX)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(iparecomp)

add_executable(myport_host iparecomp/tools/ipa_host.cpp)
target_link_libraries(myport_host PRIVATE iparecomp)

# The lifted program, when it has been generated.
file(GLOB LIFTED CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/generated/*.c")
if(LIFTED)
  add_library(lifted STATIC ${LIFTED})
  target_include_directories(lifted PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/generated")
  target_link_libraries(lifted PUBLIC iparecomp)
  # Lifted code is generated, not written -- warnings about it are noise about
  # a decision the emitter made, and the place to fix one is the emitter.
  target_compile_options(lifted PRIVATE -w)
  # The guest backtrace. One store per lifted call, and without it a fault
  # inside hundreds of identically shaped C functions names nothing at all.
  target_compile_definitions(lifted PUBLIC ARC_FRAMES)
  target_link_libraries(myport_host PRIVATE lifted)
endif()
```

Then put the lifter's output in `generated/`, as in step 3.

## 6. Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

CMake reports what it found, and each line is a capability you either have or
do not:

```
-- iparecomp: FreeType 26.4.20 via pkg-config
-- iparecomp: libpng 1.6.54 via pkg-config
-- iparecomp: no zlib -- those imports stay on the work list
-- iparecomp: OpenGL found -- GLES 1.1 maps straight onto it
-- iparecomp: SDL2 found -- window enabled
```

On Windows add
`-DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake` so CMake
finds them. A toolchain file only takes effect on a fresh cache, so delete
`build/` if you add it later.

## 7. Run it

Unzip the `.ipa` — it is a zip — so the game can reach its own resources:

```sh
unzip "Canabalt.ipa" -d payload/
```

```sh
./build/myport_host --permissive \
    --bundle=payload/Payload/Canabalt.app \
    payload/Payload/Canabalt.app/Canabalt
```

`--permissive` answers an unimplemented framework message with nil and an
unimplemented import with zero, and writes both down. That is the point: **one
run names the whole remaining contract** instead of one rebuild per missing
symbol. Use `--run` instead to stop dead at the first missing piece.

The header tells you where you stand:

```
link base  00001000, span 0.4 MB
slide      00000000
segments   4
           __TEXT       00001000 +0x3a000  host 0000000000010000
           __DATA       0003B000 +0x9000   host 000000000003b000
shims      115 imports claimed, 32 still owed
classrefs  504 bound, 147 pointer slots filled, 24 imports given a synthetic address
entry      0x00002504
```

`115 imports claimed, 32 still owed` is the work list, and it shrinks. Then the
game starts talking, because `NSLog` works:

```
  UIApplicationMain: delegate is CanabaltAppDelegate
[guest] check for other audio!
[guest] is other audio playing: 0
run loop: driving gameLoop
```

## 8. See it draw

A frame loop is by construction a run that never finishes, so "does it draw" is
not a question you should have to answer by watching a window. Bound the loop
and take a picture:

```sh
ARC_MAX_FRAMES=300 ARC_SHOT=menu.ppm ./build/myport_host --permissive \
    --bundle=payload/Payload/Canabalt.app \
    payload/Payload/Canabalt.app/Canabalt
```

```
run loop: 300 frames

the guest ran its launch path and called exit(0)
```

`menu.ppm` is the last frame: 480x320, the CANABALT logo, the skyline, the
SEMI SECRET billboard, and the ABOUT and PLAY buttons.

Tap one without touching the mouse:

```sh
ARC_MAX_FRAMES=300 ARC_TAP="30,400" ARC_SHOT=tapped.ppm ./build/myport_host ...
```

```
[touch] touchesBegan:withEvent: at (30,400)
[touch] touchesEnded:withEvent: at (30,400)
```

`ARC_TAP` takes a list — `x,y,frame;x,y,frame` — and with `ARC_SHOT_EVERY=n`
writing every nth frame, a walk through the menus becomes a recording that
repeats exactly: no window chrome, no cursor, the same frames every time. The
full set of knobs is in the [README](../README.md#driving-a-run-without-a-person-at-the-keyboard).

## When it stops somewhere new

This is the loop you will spend all your time in, and the tools exist to make
each turn of it short.

**A permissive run already told you what is missing.** Read its list before
guessing. Every entry is a message the binary sent that nothing answered, or an
import nothing claimed.

**A fault gets a backtrace through lifted code** plus the trail of calls out to
the host, so you can see both what the guest was doing and what it last asked
for:

```
guest functions entered, most recent first:
  0x00023368  -[FlxText render]      <- 0x0000e40c -[FlxLayer render]
  0x0000b334  -[FlxCore visible]     <- 0x0000e3d8 -[FlxLayer render]

calls out to the host, most recent first:
  _glDrawArrays
  _glBindTexture
```

**Trace what crosses the boundary.** `ARC_TRACE_MSG=<substr>` prints the
Objective-C messages whose selector contains that substring, with their
arguments *and what they returned* — a shim returning something implausible is
the likeliest origin of a bad pointer, and only the return value shows it.
`ARC_TRACE_CALLS=<substr>` does the same for host calls.

**Answer honestly, not plausibly.** A shim that returns a made-up success makes
the guest take a path its authors never tested. Canabalt's audio shim lets
opening a file *fail*, and the game takes the no-sound path it has always had:

```
[guest] Error opening file (bomb_explode.caf): 2003334207
```

Those errors are the shim being correct.

## Known limits

Worth knowing before you pick a title.

- **Stripped binaries do not lift yet.** `LC_FUNCTION_STARTS` is parsed and
  reported, but boundaries and the ARM/Thumb split are taken from the symbol
  table, so a binary with no symbols analyses as zero functions even when
  thousands of starts are recorded. This is the main thing standing between the
  toolkit and post-2011 titles.
- **Interworking is lifted but not yet exercised on a real target.** Canabalt
  is 0% Thumb by design, so the mixed-mode path has no port behind it yet.
- **Some PNGs in a shipped `.ipa` are Apple's CgBI variant** and libpng refuses
  them (`libpng error: CgBI: unhandled critical chunk`). It is a minority — 7
  of Canabalt's 73, all gameplay art — so the menu loads from a stock `.ipa`
  untouched. There is no de-cruncher here yet.
- **`ipa_host` does not link on its own with MinGW.** It reaches the lifted
  program through a weak symbol, which resolves to null on ELF and Mach-O when
  nothing defines it but is a hard link error on PE/COFF. Build it from a port
  that has a `generated/`, as in step 5, and it links.

Stuck on something not in that list? The
[Discord](https://discord.gg/CRpzGWZFcu) is the place, and
[ARCHITECTURE.md](ARCHITECTURE.md) is where the reasoning behind all of this
lives.
