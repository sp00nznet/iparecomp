# iparecomp

> A toolkit for turning old iOS apps' binaries into native desktop
> applications. Bring your own `.ipa`.

**Status: the game runs, and says so.** All 626 of Canabalt's functions
lift to C; 62,421 per-instruction and 3,000 whole-function differential cases
agree with Unicorn. The image maps at its own link address with a zero slide,
`objc_msgSend` dispatches into lifted code, and the guest now runs from
`_start` through `applicationDidFinishLaunching:` and the whole flixel setup to
`exit(0)`. What it asks for on the way is measured, not guessed: one run names
the 18 messages and 27 imports still outstanding, and they are now the window
itself -- UIScreen, UIWindow, CADisplayLink, NSRunLoop -- plus OpenGLES and
audio. See [Milestones](#milestones).

---

## What this is

The iPhone 3G era — iPhone OS 2.0 through 3.x, 2008 to 2010, when the App
Store first opened — produced a large catalogue of games that runs on nothing
today. The binaries are 32-bit ARM Mach-O, armv6 or armv7, and no current
device executes that natively. Apple dropped 32-bit support entirely in iOS 11.

That catalogue is the target. Same philosophy as
[androidrecomp](https://github.com/sp00nznet/androidrecomp), aimed at the other
platform: replace the host, satisfy the import surface, lift the machine code
to C, and get an ordinary native executable out — no emulator, no jailbreak, no
device.

**This repository is deliberately app-agnostic.** A port supplies its own
bundle contract and links the library here. Nothing title-specific belongs in
this repo — that separation is much cheaper to keep than to retrofit.

The name is the file extension, not the platform. Nothing here uses Apple's
branding, trademarks, code, headers or SDKs.

## Legal / content policy

Tools only. No app code, no app assets, no extracted art, no save data, no
publisher binaries — `.gitignore` blocks all of it, deliberately. You supply
your own legally obtained `.ipa`; everything here operates on a file you
already have. Licensed MIT; contributions must be your own work.

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

The symbol table's `N_ARM_THUMB_DEF` bit is the only reliable record of which
set each function is in, which makes a *stripped* binary considerably worse
than a merely-old one.

**3. Most control flow is `objc_msgSend`.** An iOS app dispatches dynamically
by selector, and no static analysis resolves that. So it is not lifted at all
— it becomes a shim boundary. The ObjC half of the app is answered by a
runtime while the C/C++ half is compiled, which is what makes a game with 38
classes and 866 selectors a far smaller job than its framework list suggests.

There is also no easy path: androidrecomp gets to run its target natively on an
arm64 host and debug the shim before any lifting exists. Nothing runs armv6, so
iparecomp is a lifting project from day one.

## What you get

| Piece | What it does |
|---|---|
| `tools/ipa_probe.py` | Feasibility triage for a new title: encryption status, arch slices, function count and `__text` coverage, the ARM/Thumb split, the framework list, and Objective-C weight. Reads an `.ipa` directly. |
| `tools/ipa_host.cpp` | Loads a binary and prints the outstanding-import work list, grouped by the framework that owes each symbol. |
| `runtime/macho_image` | Parses a fat or thin Mach-O, picks an ARM slice, maps its segments, records the slide, and resolves every undefined symbol to the dylib that owes it. Refuses an encrypted image by name. |
| `runtime/arm32_context.h` | Guest CPU state and the operations lifted code emits — the emitter's target. Barrel shifter with its separate carry-out, unpacked flags, condition predicates, interworking helpers. |
| `tools/lifter.py` | Lifts armv6/armv7 and Thumb-2 to C, one C function per guest function. `--report` says what fraction of *functions* lift completely, which is the number that decides whether a build is possible. |
| `tools/lift_verify.py` | Differential-tests lifted instructions against Unicorn on encodings harvested from the real binary, with the image mapped at the same address on both sides. |
| `runtime/objc_runtime` | Realizes the class table out of `__DATA` and answers `objc_msgSend` by selector, dispatching into lifted code. Reports which selectors the binary sends that nothing in it implements -- the framework contract. |
| `tools/objc_verify.py` | Checks that runtime's realized table against `objc_dump.py`, which reads the same ABI independently. |
| `runtime/arc_boot` | Starts the guest and says where it stopped: the trap, a backtrace through lifted code, and the trail of calls out to the host. |
| `runtime/arc_mem` | The guest's heap and stack, below 4 GB, because a 32-bit guest cannot hold a host pointer. |
| `runtime/objc_host` | Framework classes as real class objects in guest memory, so the guest can hold them, send to them and inherit from them. |
| `tools/objc_dump.py` | Reads the Objective-C class table straight out of `__DATA` -- classes, methods, selectors, and each method's implementation address. An iOS host contract is a set of classes, and this is how you discover one. |
| `tools/arc_selftest.c` | Checks the shifter carry and the flag helpers against real ARM semantics. The bugs it catches are silent ones. |

## Building

CMake 3.20+ and any C++17 compiler. zlib and SDL2 are optional.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

./build/arc_selftest                       # ARM semantics, no .ipa needed
./build/ipa_host path/to/Payload/Game.app/Game
```

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
```

On Windows add `-DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake`
so CMake finds zlib and SDL2. A toolchain file only takes effect on a fresh
cache, so delete `build/` if you add it later.

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
| ObjC classes / selrefs | — | 38 / 866 | — |

Canabalt being 100% ARM is why it was picked as the first port: the emitter can
be built and validated with no interworking at all, and 626 functions is small
enough to lift in full and check against an emulator.

## Milestones

- [x] **M0 — triage.** `ipa_probe.py`: encryption gate, slice selection,
      per-function ARM/Thumb disassembly, coverage, ObjC weight.
- [x] **M1 — loader.** Fat and thin Mach-O parsed, segments mapped, slide
      recorded, imports resolved to owing frameworks.
- [x] **M2 — the emitter's target.** `arm32_context.h`, with the shifter and
      flag semantics checked against hardware behaviour.
- [x] ~~**M3 — decoder.**~~ **Dropped, deliberately.** This called for a
      decoder for armv6/armv7 and Thumb-2, verified against capstone. But
      capstone already decodes all three, so the milestone amounted to building
      a worse capstone and then testing it against the real one. `lifter.py`
      emits straight from capstone's operand detail, which is what
      androidrecomp's lifter does and what freed the effort for the emitter.
- [x] **M4 — emitter.** 626 of 626 functions, 41,167 of 41,167 instructions.
      Condition codes as predicates, PC reads folded to constants at lift time,
      `ldm`/`pop` writing PC recognised as return or indirect branch, and the
      whole VFP surface these binaries use. The output compiles clean at
      `-Wall`.
- [x] **M5 — differential test.** Per instruction: 62,421 cases over 159
      operand forms, 100% agreement with Unicorn on registers, flags, the
      vector file and memory. Whole functions: 3,000 cases over 150 of
      Canabalt's 152 self-contained functions, also 100%.
- [x] **M6 — the slide.** These binaries are non-PIE with an empty rebase
      table, so nothing records which words are pointers and the image cannot
      be slid at all -- but its link address is below the 64 KB floor every
      desktop OS enforces. Solved exactly, with no heuristic: the lifter folds
      all 5,852 literal-pool loads into constants, which leaves `__TEXT,__text`
      -- the only section below the floor -- with no run-time reader at all.
      The loader then maps every segment at its link address from `0x10000` up,
      the slide is zero, and the unmappable first 64 KB serves as the guard
      page. See
      [The slide has to be zero](docs/ARCHITECTURE.md#the-slide-has-to-be-zero).
- [x] **M7 — ObjC runtime.** 49 classes and their metaclasses realized from
      `__objc_classlist`, categories merged, and the superclass chain named
      even where it leaves the binary -- a class inheriting `NSObject` has a
      zero superclass field and a bind entry saying so, so the bind opcodes are
      read too. `objc_msgSend`, `objc_msgSendSuper2` and `objc_msgSend_stret`
      are registered at their import stubs, so lifted code that sends a message
      dispatches into other lifted code. Checked two ways: the realized table
      agrees with `objc_dump.py`, an independent reader, on all 49 classes and
      518 method pairs; and 88/88 real messages sent through the stub, the
      native table and the runtime arrive at the implementation the table
      names.
- [ ] **M8 — framework shims.** The scaffolding is in and the game runs on it;
      the frameworks themselves are the remaining work.
      - [x] A guest heap and stack below 4 GB, because a 32-bit guest cannot
            hold a host `malloc` result -- `arc_mem`.
      - [x] libSystem and libgcc: all 13 symbols Canabalt names.
      - [x] Host classes with real class objects in guest memory, and the 220
            framework class references dyld would have bound now bound to them.
      - [x] `UIApplicationMain` far enough to reach the delegate, and NSObject's
            `alloc`/`init`/`retain`/`release`/`isKindOfClass:`.
      - [x] `--run` starts the guest and says where it stopped, with a
            backtrace through lifted code and the trail of calls out.
      - [x] `--permissive` answers an unimplemented framework message with nil
            and an unimplemented import with zero, writing both down, so one
            run enumerates the whole contract instead of one rebuild per
            symbol.
      - [x] Foundation enough to launch: NSString with a format implementation,
            NSNumber, NSDictionary, NSUserDefaults, NSBundle, NSURL.
      - [x] A category on a framework class answers from lifted code --
            `+[UIColor(HexColor) colorWithHexRed:...]` is the game's own.
      - [x] OpenGLES on desktop GL. Every entry point the game uses is also
            OpenGL 1.1 under the same name, so the shims are calls rather than
            a translation layer and `opengl32` resolves them with no loader.
      - [x] An SDL window with a compatibility GL context, and a frame loop
            standing in for CADisplayLink and NSRunLoop.
      - [x] UIScreen, UIWindow, UIView with a real class hierarchy, EAGLContext,
            CAEAGLLayer.
      - [x] Audio answered honestly rather than plausibly: the session
            succeeds, opening a file fails, and the game takes its own
            no-sound path.
      - [x] CoreGraphics geometry, written out exactly -- empty rectangles
            compare equal, containment is half-open, an inset past the middle
            is the null rect.
      - [x] Images: the bundle's 73 PNGs decoded with libpng, the bitmap
            context the game composes textures in, and the blit into it that
            `glTexImage2D` then uploads.
      - [x] `--bundle` so resources resolve, and a function budget so a guest
            that never reaches the frame loop reports where it was going round
            instead of hanging.
      - [x] Fonts backed by FreeType, out of the bundle's own Nokia.ttf --
            real advances and bounding boxes in font units, and glyphs
            rasterised into the same bitmap context the game uploads.
      - [x] NSArray and NSMutableArray for real, including fast enumeration,
            because `for (x in array)` is everywhere and an array that stays
            silently empty is a menu with no buttons in it.
      - [ ] Text layout still faults. The run now gets through the menu's
            buttons and into `-[SSText setText:]`, where it reads a wild
            pointer -- reported, with the address and what the OS says is at
            it, by the fault handler rather than as a bare crash.

      Canabalt now runs from `_start` through the whole launch, the audio
      load loop, the GL view and framebuffer setup, texture loading, sprite
      construction, the high-score store and the menu's buttons, and into text
      layout -- **113 imports answered, 34 to go**. It prints its own
      diagnostics along the way, because `NSLog` works:

      ```
      [guest] check for other audio!
      [guest] is other audio playing: 0
      [guest] Error opening file (bomb_explode.caf): 2003334207
      ```

      Those audio errors are the shim being honest rather than plausible, and
      the game taking the path it has for a device with no sound available.
- [ ] **M9 — a window.**

## Ports

- [canabaltrecomp](https://github.com/sp00nznet/canabaltrecomp) — Canabalt
  (Semi Secret Software, 2009). 626 functions, no interworking, 14 frameworks.
  Chosen as the **emitter's calibration target**: Semi Secret open-sourced the
  game in full, so the original armv6 binary and the source it was built from
  are both available. Lifted output can be checked against ground truth, which
  is not normally possible.

Angry Birds (armv6, decrypted, 3,633 functions, 21% Thumb) is the first real
preservation port, once the emitter handles interworking.
