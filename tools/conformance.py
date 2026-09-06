#!/usr/bin/env python3
"""Emitter conformance suite: fixed encodings, no `.ipa` required.

Every other check in this repository needs a binary you supplied.
`lift_verify.py` harvests encodings from a real image, `lift_verify_fn.py`
runs whole functions out of one, and `objc_verify.py` reads a real class
table. All three are the right tests and none of them can run on a clean
checkout, which means a change to the emitter cannot be checked by anyone who
does not already own a suitable game.

This is the suite that can. The encodings below are written down rather than
harvested, chosen to pin the semantics that 32-bit ARM gets wrong quietly --
the ones that produce a plausible number instead of a crash. Each is lifted by
the real emitter and run against Unicorn through the same harness
`lift_verify.py` uses, so a pass here means the same thing a pass there does.

    python tools/conformance.py            # run them
    python tools/conformance.py --list     # just show what each encoding is

What it deliberately does not cover: anything with control flow. The harness
runs one instruction in isolation, and a branch leaves the case. Returns,
`pop {pc}` and the dispatcher are covered by lift_verify_fn.py on a real
binary.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lift_verify as V  # noqa: E402

try:
    import lifter as L
except ImportError:
    sys.exit("need the lifter: run this from the repository")


# Where the synthetic instructions live. Above IMAGE_FLOOR so the address is
# one a real image could have, which matters because PC-relative reads are
# folded against it at lift time.
CODE_ADDR = 0x11000


# (name, encoding, thumb, what it pins)
#
# Encodings are written most-significant-byte first, the way a disassembler
# prints them; `--list` shows what each one actually decodes to, which is how
# a typo in this table is caught rather than silently testing the wrong thing.
CASES = [
    # ----------------------------------------------------------------- ARM
    # 1. Every instruction is conditional, and the condition is a predicate
    #    over flags the previous instruction may have set.
    ("cond: addeq", 0x00810002, False, "an untaken instruction changes nothing"),
    ("cond: movne", 0x13A00001, False, "immediate move under a condition"),
    ("cond: adds", 0xE0910002, False, "S=1 writes all four flags"),
    ("cond: cmp", 0xE1500001, False, "subtract that keeps only the flags"),

    # 2. The barrel shifter has a carry-out of its own, separate from the
    #    ALU's, and the encodings for shift-by-32 and RRX are special cases
    #    that a naive `<<` gets wrong.
    ("shift: movs lsl #1", 0xE1B00081, False, "shifter carry, not ALU carry"),
    ("shift: movs lsr #32", 0xE1B00021, False, "lsr #32 is encoded as #0"),
    ("shift: movs asr #32", 0xE1B00041, False, "asr #32 is encoded as #0"),
    ("shift: movs rrx", 0xE1B00061, False, "rotate through carry, 1 bit"),
    ("shift: ands lsl #3", 0xE0110182, False, "shifted operand sets carry"),
    ("shift: orrs asr #4", 0xE1910242, False, "arithmetic shift keeps sign"),
    ("shift: movs lsl r2", 0xE1B00211, False, "register shift amount"),

    # 3. A scaled register index. This is the one that shipped: `lsl #2` was
    #    dropped from the address, so every array subscript in the binary read
    #    one byte into an element instead of one element along. Capstone
    #    reports the scale in the operand's `shift` and leaves `mem.lshift`
    #    zero, and 62,421 agreeing cases did not catch it because the form key
    #    rendered every addressing mode the same.
    ("addr: ldr [r,r lsl #2]", 0xE7935106, False, "THE regression"),
    ("addr: str [r,r lsl #2]", 0xE7810102, False, "the same, storing"),
    ("addr: ldrb [r,r lsl #1]", 0xE7D10082, False, "scaled, byte-sized"),
    ("addr: ldr [r,#imm]", 0xE5910004, False, "immediate offset"),
    ("addr: ldr [r,r]", 0xE7910002, False, "unscaled register offset"),
    ("addr: ldr [r,#imm]!", 0xE5B10004, False, "pre-index writes the base"),
    ("addr: ldr [r],#imm", 0xE4910004, False, "post-index writes the base"),
    ("addr: ldrh [r,#imm]", 0xE1D100B4, False, "halfword, its own encoding"),
    ("addr: ldrsb [r,#imm]", 0xE1D100D4, False, "sign-extending load"),

    # 3b. A 32-bit constant with no literal pool: movw builds the bottom half
    #     and movt the top, and movt has to keep the half it is not writing.
    ("const: movw", 0xE3010234, False, "16-bit immediate, top cleared"),
    ("const: movt", 0xE3410234, False, "top half, bottom preserved"),

    # 4. The PC is a general register, and reads of it are folded to constants
    #    at lift time -- which is only correct if the constant is the one the
    #    hardware would have produced.
    ("pc: add r0, pc, #8", 0xE28F0008, False, "PC reads as addr + 8"),

    # 5. Multiplies, where the long forms write two registers and the flags
    #    behave unlike the ALU's.
    ("mul: mul", 0xE0000291, False, "32-bit multiply"),
    ("mul: umull", 0xE0810392, False, "unsigned 64-bit, two destinations"),
    ("mul: smull", 0xE0C10392, False, "signed 64-bit, two destinations"),
    ("mul: mla", 0xE0210392, False, "multiply-accumulate"),

    # 6. Carry in and out, where C is an input as well as an output and the
    #    borrow convention is inverted from x86's.
    ("carry: adcs", 0xE0B10002, False, "carry in and out"),
    ("carry: sbcs", 0xE0D10002, False, "subtract is not borrow"),
    ("carry: rsb #0", 0xE2610000, False, "reverse subtract, negate"),
    ("carry: rscs", 0xE0F10002, False, "reverse subtract with carry"),
    ("carry: adc (no S)", 0xE0A10002, False, "carry in, flags untouched"),
    ("carry: mvns", 0xE1F00001, False, "bitwise not, sets flags"),
    ("carry: bic", 0xE1C10002, False, "clear the bits of the mask"),

    # 7. Block transfers, which move an arbitrary set of registers and may
    #    write back a base that is itself in the set.
    ("block: ldm", 0xE891000D, False, "load multiple"),
    ("block: stm", 0xE881000D, False, "store multiple"),
    ("block: ldmdb", 0xE911000D, False, "decrement before"),

    # 8. Extension and reversal, which are single instructions on ARM and
    #    several on a host that lacks them.
    ("ext: uxtb", 0xE6EF0071, False, "zero-extend a byte"),
    ("ext: sxth", 0xE6BF0071, False, "sign-extend a halfword"),
    ("ext: rev", 0xE6BF0F31, False, "byte reverse"),
    ("ext: clz", 0xE16F0F11, False, "count leading zeroes"),

    # --------------------------------------------------------------- Thumb
    # The other instruction set in the same binary. Canabalt is 0% Thumb, so
    # nothing else in this repository exercises these on a real target.
    ("thumb: adds r0,r1,r2", 0x1888, True, "16-bit three-register add"),
    ("thumb: lsls #3", 0x00C8, True, "16-bit shift, sets flags"),
    ("thumb: ldr [r1,r2]", 0x5888, True, "16-bit register offset"),
    ("thumb: ldr [r1,#4]", 0x6848, True, "16-bit immediate offset"),
    ("thumb: subs #imm", 0x3901, True, "immediate, sets flags"),
    ("thumb: ands", 0x4008, True, "16-bit bitwise and"),
]


def encode(word: int, thumb: bool) -> bytes:
    """Little-endian bytes, as they would sit in __text."""
    if thumb and word <= 0xFFFF:
        return word.to_bytes(2, "little")
    if thumb:                       # 32-bit Thumb-2: two halfwords, each LE
        return ((word >> 16) & 0xFFFF).to_bytes(2, "little") + \
               (word & 0xFFFF).to_bytes(2, "little")
    return word.to_bytes(4, "little")


STRIDE = 8          # per case, so each has its own address in the image


def layout(only: str):
    """Assign every selected case its own address, and build the image.

    The oracle executes the instruction by *reading it out of the image* at
    `case.addr`, so the encodings have to actually be there. An image of zeros
    decodes as `andeq r0, r0, r0` -- a no-op that quietly passes nothing.
    """
    chosen = [(n, w, t, y) for n, w, t, y in CASES if not only or only in n]
    span = V.align_up(len(chosen) * STRIDE + V.PAGE)
    buf = bytearray(CODE_ADDR - V.IMAGE_BASE + span)
    placed = []
    for i, (name, word, thumb, why) in enumerate(chosen):
        addr = CODE_ADDR + i * STRIDE
        raw = encode(word, thumb)
        buf[addr - V.IMAGE_BASE:addr - V.IMAGE_BASE + len(raw)] = raw
        placed.append((name, why, addr, thumb, raw))
    return placed, bytes(buf)


def build_cases(lf, placed):
    """One Case per table entry, lifted by the real emitter."""
    cases, skipped = [], []
    for name, why, addr, thumb, raw in placed:
        lf.thumb = thumb
        try:
            insns = lf.decode(raw, addr, thumb)
        except Exception as exc:                       # noqa: BLE001
            skipped.append((name, f"does not decode: {exc}"))
            continue
        if addr not in insns:
            skipped.append((name, "decoded to nothing"))
            continue
        ins = insns[addr]
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        try:
            body = lf.instruction(ins, {addr})
        except L.Unsupported as exc:
            skipped.append((name, f"no emitter: {text} ({exc})"))
            continue
        # The harness runs one instruction with nothing after it, so anything
        # that leaves the instruction has nowhere to go.
        if any(t in body for t in ("arc_dispatch", "return;", "goto ",
                                   "arc_trap", "fn_")):
            skipped.append((name, f"control flow, not testable here: {text}"))
            continue
        cases.append((name, why, V.Case(addr, ins.size, text,
                                        L.form(ins), body, thumb)))
    return cases, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", type=int, default=24,
                    help="starting states per encoding")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", default="", help="only cases whose name contains")
    ap.add_argument("--list", action="store_true",
                    help="show what each encoding decodes to, and stop")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    # No image to load, so the addresses the harness would take from one are
    # set here. A synthetic image is enough: nothing in the table reads it,
    # because every load and store is aimed at the harness's scratch page.
    V.LINK_BASE = V.IMAGE_BASE = 0x1000
    placed, image = layout(args.only)
    image_size = V.align_up(V.IMAGE_BASE + len(image)) - V.IMAGE_BASE
    image = image.ljust(image_size, bytes(1))

    lf = L.Lifter()
    lf.link_base = V.IMAGE_BASE
    lf.image = image
    lf.ro_range = (CODE_ADDR, CODE_ADDR + len(placed) * STRIDE)

    cases, skipped = build_cases(lf, placed)

    if args.list:
        for name, why, case in cases:
            print(f"  {name:<26} {case.text:<28} {case.form:<20} {why}")
        for name, why in skipped:
            print(f"  {name:<26} SKIPPED -- {why}")
        return 0

    for name, why in skipped:
        print(f"  skipped: {name} -- {why}")
    if not cases:
        sys.exit("no cases to run")

    print(f"conformance: {len(cases)} encodings, {args.seeds} states each")
    bad = V.verify([c for _, _, c in cases], image, image_size,
                   args.seeds, args.seed, args.keep)
    if skipped and not bad:
        print(f"\n{len(skipped)} case(s) skipped -- see above")
    return bad


if __name__ == "__main__":
    sys.exit(main() and 1)
