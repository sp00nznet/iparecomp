# Triage: `angrybirdsrio`

- bundle: `com.rovio.angrybirdsrio` 1.0.0
- slices: 1 (armv6)
- analysed: **armv6**, min iPhone OS unstated
- `__TEXT`: **not encrypted** (`LC_ENCRYPTION_INFO` present, cryptid=0)
- `__text`: 1.99 MB @ 0x2bb4
- `LC_FUNCTION_STARTS`: **absent** -- function boundaries must be
  recovered from the symbol table and by following calls
- symbols: 5,508 defined, 359 undefined
- functions from the symbol table: **3,633** covering 91.1% of `__text`
- instruction sets: **2,869 ARM, 764 Thumb** (21% Thumb)
- instructions: 494,331 (596 distinct mnemonics)
- undecoded bytes: 176,404

## Shim surface

Every framework here is a shim you write:

- `/System/Library/Frameworks/Foundation.framework/Foundation`
- `/System/Library/Frameworks/UIKit.framework/UIKit`
- `/System/Library/Frameworks/OpenGLES.framework/OpenGLES`
- `/System/Library/Frameworks/QuartzCore.framework/QuartzCore`
- `/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics`
- `/System/Library/Frameworks/OpenAL.framework/OpenAL`
- `/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox`
- `/System/Library/Frameworks/AddressBook.framework/AddressBook`
- `/System/Library/Frameworks/CoreLocation.framework/CoreLocation`
- `/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration`
- `/usr/lib/libz.1.dylib`
- `/System/Library/Frameworks/GameKit.framework/GameKit`
- `/usr/lib/libstdc++.6.dylib`
- `/usr/lib/libgcc_s.1.dylib`
- `/usr/lib/libSystem.B.dylib`
- `/usr/lib/libobjc.A.dylib`
- `/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation`

## Objective-C weight

| section | count |
|---|---|
| `__objc_classlist` | 38 |
| `__objc_selrefs` | 866 |
| `__objc_protolist` | 13 |
| `__objc_catlist` | 1 |

Selector references are the honest measure of how much control flow
goes through `objc_msgSend`. That dispatch is never lifted -- it is
answered by a runtime, and every one of those selectors must resolve.

## Constructs the lifter must special-case

| construct | count |
|---|---|
| interworking-branch | 7,307 |
| pc-relative-load | 28,788 |
| block-transfer | 11,179 |
| exclusive | 1 |
| barrier | 0 |
| syscall | 213 |
| coprocessor | 217 |
| status-register | 2 |

## Top mnemonics

| mnemonic | count |
|---|---|
| `ldr` | 106,512 |
| `add` | 55,037 |
| `str` | 48,923 |
| `cmp` | 40,373 |
| `mov` | 32,002 |
| `bl` | 25,340 |
| `beq` | 23,437 |
| `adds` | 16,849 |
| `sub` | 13,218 |
| `ble` | 8,982 |
| `b` | 8,320 |
| `strb` | 7,920 |
| `ldrb` | 7,756 |
| `movs` | 7,019 |
| `blx` | 6,090 |
| `vldr` | 5,982 |
| `bne` | 4,529 |
| `lsl` | 4,389 |
| `pop` | 4,277 |
| `push` | 4,062 |
| `mvn` | 3,600 |
| `andeq` | 2,710 |
| `vstr` | 2,665 |
| `andseq` | 2,247 |
| `vmul.f32` | 2,045 |
