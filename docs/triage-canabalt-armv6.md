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
- undecoded bytes: 36,904

## Shim surface

Every framework here is a shim you write:

- `/System/Library/Frameworks/Foundation.framework/Foundation`
- `/System/Library/Frameworks/UIKit.framework/UIKit`
- `/System/Library/Frameworks/OpenGLES.framework/OpenGLES`
- `/System/Library/Frameworks/QuartzCore.framework/QuartzCore`
- `/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics`
- `/System/Library/Frameworks/AVFoundation.framework/AVFoundation`
- `/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox`
- `/System/Library/Frameworks/OpenAL.framework/OpenAL`
- `/usr/lib/libxml2.2.dylib`
- `/System/Library/Frameworks/Security.framework/Security`
- `/System/Library/Frameworks/CoreData.framework/CoreData`
- `/usr/lib/libgcc_s.1.dylib`
- `/usr/lib/libSystem.B.dylib`
- `/usr/lib/libobjc.A.dylib`
- `/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation`

## Objective-C weight

| section | count |
|---|---|
| `__objc_classlist` | 49 |
| `__objc_selrefs` | 506 |
| `__objc_protolist` | 7 |
| `__objc_catlist` | 7 |

Selector references are the honest measure of how much control flow
goes through `objc_msgSend`. That dispatch is never lifted -- it is
answered by a runtime, and every one of those selectors must resolve.

## Constructs the lifter must special-case

| construct | count |
|---|---|
| interworking-branch | 203 |
| pc-relative-load | 4,658 |
| block-transfer | 1,913 |
| exclusive | 0 |
| barrier | 0 |
| syscall | 69 |
| coprocessor | 23 |
| status-register | 2 |

## Top mnemonics

| mnemonic | count |
|---|---|
| `ldr` | 11,761 |
| `mov` | 5,063 |
| `bl` | 3,564 |
| `andeq` | 2,414 |
| `add` | 2,159 |
| `str` | 1,928 |
| `vmov` | 1,207 |
| `sub` | 750 |
| `push` | 591 |
| `pop` | 572 |
| `vldr` | 534 |
| `cmp` | 527 |
| `muleq` | 436 |
| `ldm` | 410 |
| `beq` | 390 |
| `strh` | 291 |
| `b` | 236 |
| `strheq` | 208 |
| `bx` | 199 |
| `stm` | 193 |
| `bne` | 185 |
| `vmrs` | 183 |
| `ldrdeq` | 176 |
| `strdeq` | 172 |
| `vstr` | 149 |
