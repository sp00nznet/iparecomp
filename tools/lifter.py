#!/usr/bin/env python3
"""Lift 32-bit ARM machine code to C.

There is no decoder here, on purpose. Capstone already decodes armv6, armv7 and
Thumb-2, and writing another one to check against it would be building a worse
capstone. This lifter emits straight from capstone's operand detail
instead. What is new on 32-bit ARM is everything *after* the
decode: a condition code on every instruction, a barrel shifter with its own
carry, a PC that is a general register, and functions that end in `pop {pc}`.

Function boundaries come from the symbol table, because these binaries predate
LC_FUNCTION_STARTS. That has a consequence the ARM64 side never faced: a
symbol-delimited function includes the literal pool sitting at its end, and a
pool disassembles as plausible nonsense -- a word of zeroes is `andeq r0, r0,
r0`, which is why that mnemonic is the fourth most common in the binary. So
reachability is walked from the entry point and only reachable instructions are
lifted or counted. Without that, data is reported as missing emitter coverage
forever and the number never converges.

    python tools/lifter.py Canabalt.ipa --report
    python tools/lifter.py Canabalt.ipa --out generated/

`--report` is the number that matters while the emitters are being filled in.
It leads with *function* completeness, not instruction coverage: a single
unsupported instruction fails the whole function it sits in, so the two move
very differently and only the first decides whether a build is possible.
"""
from __future__ import annotations

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ipa_probe as probe  # noqa: E402

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    from capstone import CS_MODE_LITTLE_ENDIAN
    from capstone import arm as ca
except ImportError:
    sys.exit("need capstone: pip install capstone")

# Capstone's condition enum in encoding order, as the ARC_COND_* macro suffix.
CC_MACRO = [None, "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
            "HI", "LS", "GE", "LT", "GT", "LE", "AL"]
# What capstone actually spells into the mnemonic, which is not always the
# macro name: `hs` and `cs` are the same condition, as are `lo` and `cc`.
CC_SUFFIX = [(), ("eq",), ("ne",), ("cs", "hs"), ("cc", "lo"), ("mi",), ("pl",),
             ("vs",), ("vc",), ("hi",), ("ls",), ("ge",), ("lt",), ("gt",),
             ("le",), ("al",)]

REGS = {f"r{i}": i for i in range(16)}
REGS.update({"sb": 9, "sl": 10, "fp": 11, "ip": 12, "sp": 13, "lr": 14, "pc": 15})

# Shift kinds in capstone's enum order. The _REG forms take the amount from a
# register, so the amount is not known at lift time and the helper must be
# called rather than inlined.
SFT = {1: "asr", 2: "lsl", 3: "lsr", 4: "ror", 5: "rrx",
       6: "asr", 7: "lsl", 8: "lsr", 9: "ror", 10: "rrx"}
SFT_REG = {6, 7, 8, 9, 10}

ALU3 = {"add", "adc", "sub", "sbc", "rsb", "rsc", "and", "orr", "eor", "bic"}
ALU2 = {"mov", "mvn", "movw", "movt"}
TEST = {"cmp", "cmn", "tst", "teq"}
SHIFTOP = {"lsl", "lsr", "asr", "ror", "rrx"}
# (bytes, signed) for each load/store width.
WIDTH = {"": (4, False), "b": (1, False), "h": (2, False),
         "sb": (1, True), "sh": (2, True)}


class Unsupported(Exception):
    """Raised by an emitter that does not handle this instruction's shape."""


def form(ins) -> str:
    """A short key describing an instruction's shape, for the report.

    Mnemonic plus operand kinds. Enough to group the tail into things worth
    writing an emitter for, without listing every register combination
    separately and drowning the signal.
    """
    kinds = []
    for op in ins.operands:
        if op.type == ca.ARM_OP_REG:
            kinds.append(f"r<{SFT[op.shift.type]}>" if op.shift.type else "r")
        elif op.type == ca.ARM_OP_IMM:
            kinds.append("i")
        elif op.type == ca.ARM_OP_MEM:
            # The addressing mode is part of the shape, not an incidental
            # detail. Collapsing every `ldr` into one key meant the harvester
            # took whichever encodings came first -- all immediate-offset ones
            # -- and a scaled register index was never sampled at all. A whole
            # addressing mode went untested, and the lost `lsl #2` on every
            # array subscript in the binary lived there.
            mode = "[m"
            if op.mem.index:
                mode += "+r"
                if op.shift.type:
                    mode += f"<{SFT[op.shift.type]}>"
                elif op.mem.lshift:
                    mode += "<lsl>"
            elif op.mem.disp:
                mode += "+d"
            kinds.append(mode + "]")
        elif op.type == ca.ARM_OP_FP:
            kinds.append("f")
        else:
            kinds.append(f"?{op.type}")
    return f"{ins.mnemonic.split('.')[0]} {','.join(kinds)}"


class Lifter:
    def __init__(self) -> None:
        self.md = {}
        for thumb, mode in ((False, CS_MODE_ARM), (True, CS_MODE_THUMB)):
            md = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
            md.detail = True
            self.md[thumb] = md
        self.unsupported: collections.Counter = collections.Counter()
        # Which form was responsible for breaking how many *functions*. Late in
        # the tail, how widely a form is spread matters far more than how often
        # it occurs: on the ARM64 side, PC-relative literal loads were a tenth
        # of a percent of instructions and seven points of function
        # completeness, because they appear about once per function.
        self.blamed: collections.Counter = collections.Counter()
        self.starts: set[int] = set()
        self.referenced: set[int] = set()
        self.insns_total = 0
        self.insns_lifted = 0
        self.link_base = 0
        self.thumb = False
        # The image itself, so a literal-pool load can be resolved while
        # lifting rather than at run time. Set by load(); without it the fold
        # simply does not happen and the load is emitted as a load.
        self.image: bytes = b""
        self.ro_range = (0, 0)   # the read-only span a fold is allowed inside
        # Resolved switch tables for the function being lifted, keyed by
        # the address of the load that reads them. Filled by reachable(),
        # which is the pass that has to follow them anyway.
        self.tables: dict[int, list[int]] = {}
        self.folded = 0

    # --- naming ------------------------------------------------------------

    @staticmethod
    def name(addr: int) -> str:
        return f"fn_{addr:08x}"

    def strip_cc(self, ins) -> str:
        """The mnemonic with only its condition suffix removed."""
        m = ins.mnemonic.split(".")[0]
        if ins.cc and ins.cc != ca.ARM_CC_AL:
            for suffix in CC_SUFFIX[ins.cc]:
                if m.endswith(suffix) and len(m) > len(suffix):
                    return m[:-len(suffix)]
        return m

    def sets_flags(self, ins) -> bool:
        """Whether this instruction *writes* the flags.

        capstone reports `update_flags` for adc, sbc and rsc even when S is
        clear, because those three *read* the carry -- so the field means
        "touches CPSR", not "writes it". Trusting it makes `adc` clobber the
        flags of the instruction after it, which is a silent wrong answer of
        exactly the kind this emitter exists to avoid. For those three the
        mnemonic is authoritative: only the S form carries the trailing `s`.
        """
        if not ins.update_flags:
            return False
        if self.root(ins) not in ("adc", "sbc", "rsc"):
            return True
        return self.strip_cc(ins).endswith("s")

    def root(self, ins) -> str:
        """The mnemonic with its condition and flag suffixes removed.

        One emitter then serves all sixteen predicated forms of an instruction
        rather than sixteen near-copies.
        """
        m = self.strip_cc(ins)
        # The trailing `s` is the flag suffix only where the architecture has
        # one. VFP does not, and `vmrs`/`mrs` end in an `s` that is part of the
        # name -- stripping it there invents a mnemonic no emitter answers to.
        if ins.update_flags and m.endswith("s") and len(m) > 1                 and not m.startswith("v") and m not in ("mrs", "msr"):
            m = m[:-1]
        return m

    # --- operands ----------------------------------------------------------

    def reg(self, ins, r) -> int:
        n = ins.reg_name(r)
        if n not in REGS:
            raise Unsupported(f"register {n}")
        return REGS[n]

    def pc_value(self, ins) -> int:
        """What r15 reads as: the pipeline offset of the machine that defined
        the encoding. Plus 8 in ARM, plus 4 in Thumb, and a Thumb literal load
        aligns the base down to a word first."""
        if not self.thumb:
            return ins.address + 8
        return ins.address + 4

    def img(self, absolute: int) -> str:
        """An address the instruction stream derived from the PC.

        These binaries were linked to load at a fixed address, so a literal-pool
        constant is a real address in the original layout. Emitted relative to
        where the image actually landed, which keeps the output valid if the
        loader ever has to slide it.
        """
        return f"(c->image_base + {absolute - self.link_base:#x}u)"

    def read(self, ins, n: int) -> str:
        """Read register `n`, folding a PC read to a constant. The emitter
        knows where the instruction is, so r15 is never a runtime value."""
        return self.img(self.pc_value(ins)) if n == 15 else f"ARC_R(c, {n})"

    def shifted(self, ins, op) -> tuple[str, str | None]:
        """(value, shifter carry-out) for a register run through the shifter.

        The carry comes back separately because it is *not* the ALU carry: a
        flag-setting logical instruction writes C from here and the ALU never
        produced one. `None` means the shifter did not touch C, which is what a
        plain register operand -- `LSL #0` -- must do, and getting that wrong
        clobbers the carry between a compare and the instruction consuming it.
        """
        base = self.read(ins, self.reg(ins, op.reg))
        kind = op.shift.type
        if not kind:
            return base, None
        name = SFT[kind]
        if name == "rrx":
            call = f"arc_rrx({base}, c->cf)"
            return f"{call}.value", f"{call}.carry"
        if kind in SFT_REG:
            amount = self.read(ins, self.reg(ins, op.shift.value))
        else:
            amount = f"{op.shift.value}u"
        call = f"arc_{name}({base}, {amount}, c->cf)"
        if kind not in SFT_REG and name != "ror" and 1 <= op.shift.value <= 31:
            # A constant amount in range is a plain C shift the host compiler
            # sees straight through. Out of range it is not: `LSR #0` encodes
            # LSR #32, and shifting a uint32_t by 32 in C is undefined.
            if name == "asr":
                value = f"(uint32_t)((int32_t){base} >> {op.shift.value})"
            else:
                value = f"({base} {'<<' if name == 'lsl' else '>>'} {op.shift.value})"
            return value, f"{call}.carry"
        return f"{call}.value", f"{call}.carry"

    def operand(self, ins, op) -> tuple[str, str | None]:
        if op.type == ca.ARM_OP_REG:
            return self.shifted(ins, op)
        if op.type == ca.ARM_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            # ponytail: a modified immediate carries its own rotation, and a
            # rotated one writes C from bit 31 while an unrotated one leaves C
            # alone. Capstone returns the folded value and not the rotation, so
            # this recovers it from whether one was needed -- anything under 256
            # was encodable without. If a differential run ever disagrees,
            # decode the rotate field out of the raw bytes instead.
            return f"{v:#x}u", (None if v < 256 else f"{v >> 31}u")
        raise Unsupported(f"operand type {op.type}")

    def dest(self, ins, op) -> int:
        return self.reg(ins, op.reg)

    # --- writing a destination that might be the PC ------------------------

    def write(self, rd: int, value: str) -> str:
        """Assign to a destination register. Writing r15 is a branch, so it is
        emitted as one rather than as a store nothing would ever read."""
        if rd == 15:
            return f"arc_dispatch(c, {value}); return;"
        return f"ARC_W(c, {rd}, {value});"

    # --- emitters ----------------------------------------------------------

    def _alu3(self, ins, op: str) -> str:
        ops = ins.operands
        if len(ops) == 2:
            ops = [ops[0], ops[0], ops[1]]
        if len(ops) != 3:
            raise Unsupported(form(ins))
        rd = self.dest(ins, ops[0])
        a = self.read(ins, self.reg(ins, ops[1].reg))
        b, carry = self.operand(ins, ops[2])
        # adc/sbc/rsc take the carry as an *input*, and the flag helpers
        # write c->cf as an output. Reading c->cf in the result expression
        # after calling one of them reads the carry the instruction just
        # produced instead of the one it was given -- wrong by exactly one,
        # and only when S is set. Latch it first.
        carry_in = op in ("adc", "sbc", "rsc")
        latch = ", ci = c->cf" if carry_in else ""
        arith = {"add": ("+", "arc_add_flags(c, a, b, 0)"),
                 "adc": ("+", "arc_add_flags(c, a, b, ci)"),
                 "sub": ("-", "arc_sub_flags(c, a, b, 1)"),
                 "sbc": ("-", "arc_sub_flags(c, a, b, ci)")}
        logic = {"and": "&", "orr": "|", "eor": "^"}
        if op in ("rsb", "rsc"):
            a, b = b, a
            flags = "arc_sub_flags(c, a, b, 1)" if op == "rsb" \
                else "arc_sub_flags(c, a, b, ci)"
            expr = "a - b - (1u - ci)" if op == "rsc" else "a - b"
            body = f"uint32_t a = {a}, b = {b}{latch}; "
            if self.sets_flags(ins):
                body += f"{flags}; "
            return "{ " + body + self.write(rd, expr) + " }"
        if op in arith:
            sign, flags = arith[op]
            expr = f"a {sign} b"
            if op == "adc":
                expr = "a + b + ci"
            elif op == "sbc":
                expr = "a - b - (1u - ci)"
            body = f"uint32_t a = {a}, b = {b}{latch}; "
            if self.sets_flags(ins):
                body += f"{flags}; "
            return "{ " + body + self.write(rd, expr) + " }"
        if op in logic or op == "bic":
            expr = f"a {logic[op]} b" if op in logic else "a & ~b"
            body = f"uint32_t a = {a}, b = {b}, r = {expr}; "
            if self.sets_flags(ins):
                body += "ARC_NZ(c, r); "
                if carry is not None:
                    body += f"c->cf = {carry}; "
            return "{ " + body + self.write(rd, "r") + " }"
        raise Unsupported(form(ins))

    def _alu2(self, ins, op: str) -> str:
        ops = ins.operands
        if len(ops) != 2:
            raise Unsupported(form(ins))
        rd = self.dest(ins, ops[0])
        v, carry = self.operand(ins, ops[1])
        # movw is a plain move of a 16-bit immediate -- the width is a fact
        # about the encoding, not about the semantics. movt is the one form
        # here that reads its own destination: it replaces the top halfword
        # and keeps the bottom, which is how a 32-bit constant is built out of
        # a movw/movt pair when there is no literal pool to load it from.
        if op == "movt":
            cur = self.read(ins, self.reg(ins, ops[0].reg))
            body = f"uint32_t r = ({cur} & 0xffffu) | ((({v}) & 0xffffu) << 16); "
            return "{ " + body + self.write(rd, "r") + " }"
        body = f"uint32_t r = {'~' if op == 'mvn' else ''}({v}); "
        if self.sets_flags(ins):
            body += "ARC_NZ(c, r); "
            if carry is not None:
                body += f"c->cf = {carry}; "
        return "{ " + body + self.write(rd, "r") + " }"

    def _test(self, ins, op: str) -> str:
        ops = ins.operands
        if len(ops) != 2:
            raise Unsupported(form(ins))
        a = self.read(ins, self.reg(ins, ops[0].reg))
        b, carry = self.operand(ins, ops[1])
        if op == "cmp":
            return "{ uint32_t a = %s, b = %s; arc_sub_flags(c, a, b, 1); }" % (a, b)
        if op == "cmn":
            return "{ uint32_t a = %s, b = %s; arc_add_flags(c, a, b, 0); }" % (a, b)
        expr = "a & b" if op == "tst" else "a ^ b"
        body = f"uint32_t a = {a}, b = {b}, r = {expr}; ARC_NZ(c, r); "
        if carry is not None:
            body += f"c->cf = {carry}; "
        return "{ " + body + "}"

    def _shift(self, ins, op: str) -> str:
        ops = ins.operands
        rd = self.dest(ins, ops[0])
        src = self.read(ins, self.reg(ins, ops[1].reg))
        if len(ops) == 2 and ops[1].shift.type:
            # `lsl r0, r1, r2` comes back as two operands with the shift folded
            # onto the source, not as three with the amount separate. Same
            # instruction, different shape, and the shifter helper already
            # knows how to read it.
            value, carry = self.shifted(ins, ops[1])
            body = f"uint32_t r = {value}; "
            if self.sets_flags(ins):
                body += "ARC_NZ(c, r); "
                if carry is not None:
                    body += f"c->cf = {carry}; "
            return "{ " + body + self.write(rd, "r") + " }"
        if op == "rrx":
            call = f"arc_rrx({src}, c->cf)"
        else:
            if len(ops) < 3:
                raise Unsupported(form(ins))
            if ops[2].type == ca.ARM_OP_IMM:
                amount = f"{ops[2].imm & 0xFF}u"
            else:
                # A register amount is taken modulo 256, not 32: shifting by
                # 0x100 is a shift by 256 and clears the register, it does not
                # wrap round to a no-op.
                amount = f"({self.read(ins, self.reg(ins, ops[2].reg))} & 0xFFu)"
            call = f"arc_{op}({src}, {amount}, c->cf)"
        body = f"ArcShift s = {call}; "
        if self.sets_flags(ins):
            body += "ARC_NZ(c, s.value); c->cf = s.carry; "
        return "{ " + body + self.write(rd, "s.value") + " }"

    def _mul(self, ins, op: str) -> str:
        ops = ins.operands
        r = [self.reg(ins, o.reg) for o in ops if o.type == ca.ARM_OP_REG]
        if op in ("mul", "mla", "mls"):
            if op == "mul" and len(r) == 3:
                expr = f"ARC_R(c, {r[1]}) * ARC_R(c, {r[2]})"
            elif op == "mla" and len(r) == 4:
                expr = f"ARC_R(c, {r[1]}) * ARC_R(c, {r[2]}) + ARC_R(c, {r[3]})"
            elif op == "mls" and len(r) == 4:
                expr = f"ARC_R(c, {r[3]}) - ARC_R(c, {r[1]}) * ARC_R(c, {r[2]})"
            else:
                raise Unsupported(form(ins))
            body = f"uint32_t r = {expr}; "
            if self.sets_flags(ins):
                body += "ARC_NZ(c, r); "
            return "{ " + body + self.write(r[0], "r") + " }"
        if op in ("umull", "smull", "umlal", "smlal") and len(r) == 4:
            lo, hi, n, m = r
            if op[0] == "u":
                wide = f"(uint64_t)ARC_R(c, {n}) * (uint64_t)ARC_R(c, {m})"
            else:
                wide = (f"(uint64_t)((int64_t)(int32_t)ARC_R(c, {n}) * "
                        f"(int64_t)(int32_t)ARC_R(c, {m}))")
            body = f"uint64_t w = {wide}; "
            if op.endswith("lal"):
                body += (f"w += ((uint64_t)ARC_R(c, {hi}) << 32) | "
                         f"ARC_R(c, {lo}); ")
            if self.sets_flags(ins):
                body += "c->nf = (uint32_t)(w >> 63); c->zf = (w == 0); "
            body += f"ARC_W(c, {lo}, (uint32_t)w); ARC_W(c, {hi}, (uint32_t)(w >> 32)); "
            return "{ " + body + "}"
        raise Unsupported(form(ins))

    def _smulxy(self, ins, op: str) -> str:
        """smulbb/bt/tb/tt: a signed 16x16 product picked out of the halves of
        two registers. `b` is bits 15:0, `t` is bits 31:16."""
        ops = ins.operands
        rd = self.dest(ins, ops[0])
        half = op[-2:]
        def part(reg_op, which):
            v = self.read(ins, self.reg(ins, reg_op.reg))
            return f"(int32_t)(int16_t)({v}{' >> 16' if which == 't' else ''})"
        expr = f"(uint32_t)({part(ops[1], half[0])} * {part(ops[2], half[1])})"
        return self.write(rd, expr)

    def _extend(self, ins, op: str) -> str:
        """uxtb/uxth/sxtb/sxth and their accumulating forms. The optional
        `ror #n` is applied before the extension, not after."""
        ops = ins.operands
        rd = self.dest(ins, ops[0])
        acc = len(ops) == 3 and op.endswith(("ab", "ah", "ab16"))
        src_op = ops[2] if acc else ops[1]
        src = self.read(ins, self.reg(ins, src_op.reg))
        if src_op.shift.type:
            if SFT[src_op.shift.type] != "ror":
                raise Unsupported(form(ins))
            src = f"arc_ror({src}, {src_op.shift.value}u, c->cf).value"
        wide = op.endswith("h") or op.endswith("ah")
        signed = op.startswith("sxt")
        cast = ("(uint32_t)(int32_t)(int16_t)" if signed else "(uint32_t)(uint16_t)") \
            if wide else \
            ("(uint32_t)(int32_t)(int8_t)" if signed else "(uint32_t)(uint8_t)")
        expr = f"{cast}({src})"
        if acc:
            expr = f"{self.read(ins, self.reg(ins, ops[1].reg))} + {expr}"
        return self.write(rd, expr)

    def _misc(self, ins, op: str) -> str:
        ops = ins.operands
        if op in ("nop", "pld", "pldw", "pli", "dmb", "dsb", "isb", "yield"):
            return "(void)0;"
        if op == "clz":
            rd = self.dest(ins, ops[0])
            src = self.read(ins, self.reg(ins, ops[1].reg))
            return "{ uint32_t v = %s, n = 0; while (n < 32 && !(v & 0x80000000u)) " \
                   "{ v <<= 1; ++n; } %s }" % (src, self.write(rd, "n"))
        if op in ("rev", "rev16", "revsh"):
            rd = self.dest(ins, ops[0])
            v = self.read(ins, self.reg(ins, ops[1].reg))
            if op == "rev":
                expr = ("((v >> 24) | ((v >> 8) & 0xFF00u) | "
                        "((v << 8) & 0xFF0000u) | (v << 24))")
            elif op == "rev16":
                expr = ("(((v >> 8) & 0x00FF00FFu) | ((v << 8) & 0xFF00FF00u))")
            else:
                expr = "((uint32_t)(int32_t)(int16_t)(((v >> 8) & 0xFFu) | (v << 8)))"
            return "{ uint32_t v = %s; %s }" % (v, self.write(rd, expr))
        raise Unsupported(form(ins))

    # --- memory ------------------------------------------------------------

    def _mem_address(self, ins, mem_index: int) -> tuple[str, str, int]:
        """(address expression, writeback statement, base register).

        Three addressing forms, told apart by where the offset sits. If there is
        an operand *after* the memory operand the instruction is post-indexed
        and that operand is the offset; otherwise the offset is inside the
        memory operand, applied before the access, and written back only if the
        instruction says so.
        """
        ops = ins.operands
        mem = ops[mem_index].mem
        base = self.reg(ins, mem.base)
        base_expr = self.read(ins, base)

        def offset_of(op) -> str:
            if op.type == ca.ARM_OP_IMM:
                return f"{op.imm & 0xFFFFFFFF:#x}u"
            v, _ = self.shifted(ins, op)
            return f"({v})"

        post = mem_index + 1 < len(ops)
        if post:
            off = offset_of(ops[mem_index + 1])
            sub = ops[mem_index + 1].subtracted
        elif mem.index:
            idx = self.read(ins, self.reg(ins, mem.index))
            # The scale of a register index lives in the operand's shift, and
            # `mem.lshift` is zero even for `[r3, r6, lsl #2]`. Testing only
            # lshift silently drops the scale on every scaled index in the
            # binary -- which is to say on array subscripting -- and the result
            # reads one byte into an element instead of one element along.
            shift = ops[mem_index].shift
            name = SFT.get(shift.type) if shift.type else None
            if name == "rrx":
                idx = f"arc_rrx({idx}, c->cf).value"
            elif name and name != "lsl":
                idx = f"arc_{name}({idx}, {shift.value}u, c->cf).value"
            elif name == "lsl" and shift.value:
                idx = f"({idx} << {shift.value})"
            elif mem.lshift:
                idx = f"({idx} << {mem.lshift})"
            off = idx
            sub = ops[mem_index].subtracted
        else:
            off = f"{abs(mem.disp):#x}u"
            sub = mem.disp < 0

        sign = "-" if sub else "+"
        if post:
            # The access uses the base unmodified; the write-back happens after.
            return base_expr, f"ARC_W(c, {base}, {base_expr} {sign} {off});", base
        addr = f"({base_expr} {sign} {off})"
        wb = f"ARC_W(c, {base}, a);" if ins.writeback else ""
        return addr, wb, base

    def literal(self, addr: int, size: int):
        """The value at `addr`, if it is fixed for the life of the program.

        A literal-pool load reads read-only memory at an address the emitter
        already knows, so the value is a constant and can be emitted as one.
        This is exact, not a heuristic: `__TEXT` is mapped r-x and there is no
        instruction in the image that could write it.

        It matters for more than speed. `__TEXT,__text` is the only section of
        these binaries that lies below the 64 KB floor every desktop OS puts on
        low mappings, and its only run-time readers are these loads. Fold them
        and the image never needs a byte mapped below `0x10000`, which is what
        lets it load at its link address with no slide -- and a zero slide is
        what makes every unrebased absolute pointer in the file correct.
        """
        lo, hi = self.ro_range
        if not self.image or addr < lo or addr + size > hi:
            return None
        off = addr - self.link_base
        if off < 0 or off + size > len(self.image):
            return None
        chunk = self.image[off:off + size]
        return int.from_bytes(chunk, "little")

    def pc_literal(self, ins, mem_index: int, size: int):
        """The constant a PC-relative load reads, or None if it is not one."""
        ops = ins.operands
        mem = ops[mem_index].mem
        if self.reg(ins, mem.base) != 15 or mem.index or ins.writeback:
            return None
        if mem_index + 1 < len(ops):   # post-indexed: the base moves
            return None
        return self.literal(self.pc_value(ins) + mem.disp, size)

    def _load(self, ins, op: str) -> str:
        suffix = op[3:]
        if suffix not in WIDTH:
            raise Unsupported(form(ins))
        size, signed = WIDTH[suffix]
        ops = ins.operands
        mem_index = next(i for i, o in enumerate(ops) if o.type == ca.ARM_OP_MEM)
        rt = [self.reg(ins, o.reg) for o in ops[:mem_index]]
        addr, wb, _ = self._mem_address(ins, mem_index)
        macro = {1: "ARC_LD8", 2: "ARC_LD16", 4: "ARC_LD32"}[size]
        if signed:
            macro += "S"
        if len(rt) == 1 and rt[0] != 15:
            value = self.pc_literal(ins, mem_index, size)
            if value is not None:
                if signed and value >> (size * 8 - 1):
                    value -= 1 << (size * 8)
                self.folded += 1
                return self.write(rt[0], f"{value & 0xFFFFFFFF:#x}u")
        # The address goes into a temporary before anything is written back or
        # loaded. A load pair whose base register is also its first destination
        # would otherwise read its second element through the value the first
        # had just loaded -- a bug the per-instruction oracle cannot find,
        # because a form keyed on operand shapes does not record the aliasing.
        body = f"uint32_t a = {addr}; "
        if len(rt) == 1:
            if rt[0] == 15:
                # Loading the PC. Whatever it is, it is not a value: dispatch.
                return "{ " + body + wb + " arc_dispatch(c, " + macro + "(a)); return; }"
            body += wb + f" ARC_W(c, {rt[0]}, {macro}(a));"
            return "{ " + body + " }"
        if len(rt) == 2 and op == "ldrd":
            body += wb + (f" ARC_W(c, {rt[0]}, ARC_LD32(a));"
                          f" ARC_W(c, {rt[1]}, ARC_LD32(a + 4));")
            return "{ " + body + " }"
        raise Unsupported(form(ins))

    def _store(self, ins, op: str) -> str:
        suffix = op[3:]
        if suffix not in WIDTH or WIDTH[suffix][1]:
            raise Unsupported(form(ins))
        size = WIDTH[suffix][0]
        ops = ins.operands
        mem_index = next(i for i, o in enumerate(ops) if o.type == ca.ARM_OP_MEM)
        rt = [self.reg(ins, o.reg) for o in ops[:mem_index]]
        addr, wb, _ = self._mem_address(ins, mem_index)
        macro = {1: "ARC_ST8", 2: "ARC_ST16", 4: "ARC_ST32"}[size]
        body = f"uint32_t a = {addr}; "
        if len(rt) == 1:
            body += f"{macro}(a, {self.read(ins, rt[0])}); " + wb
        elif len(rt) == 2 and op == "strd":
            body += (f"ARC_ST32(a, {self.read(ins, rt[0])});"
                     f" ARC_ST32(a + 4, {self.read(ins, rt[1])}); " + wb)
        else:
            raise Unsupported(form(ins))
        return "{ " + body + " }"

    def _block(self, ins, op: str) -> str:
        """push/pop/ldm/stm.

        Registers always transfer in increasing register order at increasing
        addresses; the mode only decides where the run starts. A PC in the list
        ends the function -- which is how most functions of this era return,
        so `bx lr` cannot be treated as the terminator.
        """
        ops = ins.operands
        if op in ("push", "pop"):
            base, regs, writeback = 13, [self.reg(ins, o.reg) for o in ops], True
            mode = "db" if op == "push" else "ia"
            load = op == "pop"
        else:
            base = self.reg(ins, ops[0].reg)
            regs = [self.reg(ins, o.reg) for o in ops[1:]]
            writeback = ins.writeback
            mode = op[3:] or "ia"
            load = op.startswith("ldm")
        if not regs:
            raise Unsupported(form(ins))
        regs = sorted(regs)
        n = len(regs) * 4
        base_expr = self.read(ins, base)
        start = {"ia": f"{base_expr}", "ib": f"{base_expr} + 4u",
                 "da": f"{base_expr} - {n - 4:#x}u", "db": f"{base_expr} - {n:#x}u"}
        final = {"ia": f"{base_expr} + {n:#x}u", "ib": f"{base_expr} + {n:#x}u",
                 "da": f"{base_expr} - {n:#x}u", "db": f"{base_expr} - {n:#x}u"}
        if mode not in start:
            raise Unsupported(form(ins))
        parts = [f"uint32_t a = {start[mode]};"]
        # The write-back is computed from the original base and applied before
        # the transfers, so a base that is also in the register list ends up
        # holding the loaded value rather than the pointer.
        if writeback:
            parts.append(f"ARC_W(c, {base}, {final[mode]});")
        returns = False
        for i, r in enumerate(regs):
            at = "a" if i == 0 else f"a + {i * 4:#x}u"
            if load and r == 15:
                # ponytail: a stack pop into PC is the frame's return, and the
                # host call stack mirrors the guest's, so it is a plain C
                # return. That is right for every function this era's compilers
                # emit. It is NOT right for a computed jump staged through the
                # stack; the whole-function differential test is what would
                # catch one, and none has appeared yet.
                if base != 13:
                    parts.append(f"arc_dispatch(c, ARC_LD32({at})); return;")
                else:
                    parts.append(f"(void)ARC_LD32({at});")
                returns = True
            elif load:
                parts.append(f"ARC_W(c, {r}, ARC_LD32({at}));")
            else:
                parts.append(f"ARC_ST32({at}, {self.read(ins, r)});")
        if returns and base == 13:
            parts.append("return;")
        return "{ " + " ".join(parts) + " }"

    # --- VFP ---------------------------------------------------------------
    # armv6 means VFPv2: s0-s31 and d0-d15, no NEON. These binaries are
    # soft-float at the ABI boundary and hard-float inside, which is why the
    # file is full of `vmov s13, r0` moving bits rather than converting them.

    @staticmethod
    def vreg(ins, r):
        """(index, 's'|'d') for a VFP register, or None for a core register.

        The name is the only thing that distinguishes them, and it has a trap
        in it: `sl`, `sb` and `sp` are core registers whose names start with
        the same letter as `s0`. The digits are what decide.
        """
        n = ins.reg_name(r)
        if len(n) > 1 and n[0] in "sd" and n[1:].isdigit():
            return int(n[1:]), n[0]
        return None

    def vread(self, ins, op) -> str:
        v = self.vreg(ins, op.reg)
        if v is None:
            raise Unsupported(form(ins))
        return f"ARC_{'S' if v[1] == 's' else 'D'}(c, {v[0]})"

    def _vmov(self, ins, op: str) -> str:
        ops = ins.operands
        v = [self.vreg(ins, o.reg) if o.type == ca.ARM_OP_REG else None
             for o in ops]
        if len(ops) == 2:
            if v[0] and v[1]:
                if v[0][1] != v[1][1]:
                    raise Unsupported(form(ins))
                w = "SU" if v[0][1] == "s" else "DU"
                # A bit copy rather than an assignment through the float view:
                # `vmov.f32` must not quieten a signalling NaN in passing.
                return f"ARC_{w}(c, {v[0][0]}) = ARC_{w}(c, {v[1][0]});"
            if v[0] and not v[1]:
                return (f"ARC_SU(c, {v[0][0]}) = "
                        f"{self.read(ins, self.reg(ins, ops[1].reg))};")
            if v[1] and not v[0]:
                return self.write(self.reg(ins, ops[0].reg),
                                  f"ARC_SU(c, {v[1][0]})")
        if len(ops) == 3:
            # A double moved through two core registers, low half first.
            if v[0] and v[0][1] == "d" and not v[1] and not v[2]:
                n = v[0][0]
                return (f"ARC_SU(c, {2 * n}) = "
                        f"{self.read(ins, self.reg(ins, ops[1].reg))}; "
                        f"ARC_SU(c, {2 * n + 1}) = "
                        f"{self.read(ins, self.reg(ins, ops[2].reg))};")
            if v[2] and v[2][1] == "d" and not v[0] and not v[1]:
                n = v[2][0]
                return (self.write(self.reg(ins, ops[0].reg),
                                   f"ARC_SU(c, {2 * n})") + " " +
                        self.write(self.reg(ins, ops[1].reg),
                                   f"ARC_SU(c, {2 * n + 1})"))
        raise Unsupported(form(ins))

    def _vldst(self, ins, op: str) -> str:
        ops = ins.operands
        v = self.vreg(ins, ops[0].reg)
        if v is None:
            raise Unsupported(form(ins))
        idx, kind = v
        if op == "vldr":
            value = self.pc_literal(ins, 1, 4 if kind == "s" else 8)
            if value is not None:
                self.folded += 1
                view = "SU" if kind == "s" else "DU"
                suffix = "u" if kind == "s" else "ull"
                return f"ARC_{view}(c, {idx}) = {value:#x}{suffix};"
        addr, wb, _ = self._mem_address(ins, 1)
        if op == "vldr":
            access = (f"ARC_SU(c, {idx}) = ARC_LD32(a);" if kind == "s"
                      else f"ARC_DU(c, {idx}) = ARC_LD64(a);")
        else:
            access = (f"ARC_ST32(a, ARC_SU(c, {idx}));" if kind == "s"
                      else f"ARC_ST64(a, ARC_DU(c, {idx}));")
        return "{ uint32_t a = " + addr + "; " + access + " " + wb + " }"

    def _vblock(self, ins, op: str) -> str:
        """vpush/vpop. Doubles, eight bytes each, always through sp."""
        regs = []
        for o in ins.operands:
            v = self.vreg(ins, o.reg)
            if v is None:
                raise Unsupported(form(ins))
            regs.append(v)
        kinds = {k for _, k in regs}
        if len(kinds) != 1:
            raise Unsupported(form(ins))
        kind = kinds.pop()
        step = 8 if kind == "d" else 4
        n = len(regs) * step
        view = "SU" if kind == "s" else "DU"
        ld = "ARC_LD32" if kind == "s" else "ARC_LD64"
        st = "ARC_ST32" if kind == "s" else "ARC_ST64"
        # The new stack pointer is computed and written before the transfers,
        # so a fault part-way through leaves sp somewhere describable.
        if op == "vpush":
            parts = [f"uint32_t a = ARC_SP(c) - {n:#x}u;", "ARC_W(c, 13, a);"]
        else:
            parts = ["uint32_t a = ARC_SP(c);",
                     f"ARC_W(c, 13, a + {n:#x}u);"]
        for i, (idx, _) in enumerate(sorted(regs)):
            at = "a" if i == 0 else f"a + {i * step:#x}u"
            if op == "vpop":
                parts.append(f"ARC_{view}(c, {idx}) = {ld}({at});")
            else:
                parts.append(f"{st}({at}, ARC_{view}(c, {idx}));")
        return "{ " + " ".join(parts) + " }"

    def _vfp_arith(self, ins, op: str) -> str:
        parts = ins.mnemonic.split(".")
        if len(parts) < 2 or parts[1] not in ("f32", "f64"):
            raise Unsupported(form(ins))
        ty = parts[1]
        ops = ins.operands
        d = self.vread(ins, ops[0])
        if op in ("vneg", "vabs", "vsqrt"):
            a = self.vread(ins, ops[1])
            expr = {"vneg": f"-({a})",
                    "vabs": f"(({a}) < 0 ? -({a}) : ({a}))",
                    "vsqrt": f"arc_sqrt{ty}({a})"}[op]
            return f"{d} = {expr};"
        if len(ops) != 3:
            raise Unsupported(form(ins))
        a, b = self.vread(ins, ops[1]), self.vread(ins, ops[2])
        binop = {"vadd": "add", "vsub": "sub", "vmul": "mul", "vdiv": "div"}
        if op in binop:
            return f"{d} = arc_{binop[op]}{ty}({a}, {b});"
        # The accumulating forms. VNMLS negates the accumulator and not the
        # product, which is the opposite of what the name suggests: it is
        # -Sd + Sn*Sm, not -(Sd + Sn*Sm).
        product = f"arc_mul{ty}({a}, {b})"
        # VNMUL is the plain one of the negated family: the product itself,
        # negated. It is not an accumulate and does not read the destination.
        if op == "vnmul":
            return f"{d} = -{product};"
        if op == "vmla":
            return f"{d} = arc_add{ty}({d}, {product});"
        if op == "vmls":
            return f"{d} = arc_sub{ty}({d}, {product});"
        if op == "vnmla":
            return f"{d} = arc_sub{ty}(-({d}), {product});"
        if op == "vnmls":
            return f"{d} = arc_add{ty}(-({d}), {product});"
        raise Unsupported(form(ins))

    def _vcmp(self, ins, op: str) -> str:
        parts = ins.mnemonic.split(".")
        if len(parts) < 2 or parts[1] not in ("f32", "f64"):
            raise Unsupported(form(ins))
        ops = ins.operands
        a = self.vread(ins, ops[0])
        if ops[1].type == ca.ARM_OP_IMM:
            # The only immediate this encoding admits is zero.
            b = "0.0f" if parts[1] == "f32" else "0.0"
        else:
            b = self.vread(ins, ops[1])
        # vcmpe raises an exception on a quiet NaN and vcmp does not, which
        # moves a bit of FPSCR nothing here reads. The flags are identical.
        return f"arc_vcmp_{parts[1]}(c, {a}, {b});"

    def _vcvt(self, ins, op: str) -> str:
        parts = ins.mnemonic.split(".")
        if len(parts) != 3:
            raise Unsupported(form(ins))
        to, frm = parts[1], parts[2]
        ops = ins.operands
        dv = self.vreg(ins, ops[0].reg)
        sv = self.vreg(ins, ops[1].reg)
        if dv is None or sv is None:
            raise Unsupported(form(ins))
        if frm in ("s32", "u32"):
            # The source is the *bits* of a single register read as an integer,
            # not a float sitting in it.
            raw = f"ARC_SU(c, {sv[0]})"
            src = f"(int32_t){raw}" if frm == "s32" else raw
            cast = "(float)" if to == "f32" else "(double)"
            return f"{self.vread(ins, ops[0])} = {cast}({src});"
        if to in ("s32", "u32"):
            # Saturating, never a cast, and the destination is a single
            # register holding integer bits whichever precision it came from.
            return (f"ARC_SU(c, {dv[0]}) = "
                    f"arc_{frm}_to_{to}({self.vread(ins, ops[1])});")
        if to == "f32" and frm == "f64":
            return f"ARC_S(c, {dv[0]}) = (float)({self.vread(ins, ops[1])});"
        if to == "f64" and frm == "f32":
            return f"ARC_D(c, {dv[0]}) = (double)({self.vread(ins, ops[1])});"
        raise Unsupported(form(ins))

    def _vmrs(self, ins, op: str) -> str:
        # `vmrs apsr_nzcv, fpscr` is the only form that appears, and it is the
        # second half of every float comparison.
        if "apsr_nzcv" in ins.op_str and "fpscr" in ins.op_str:
            return "arc_vmrs_nzcv(c);"
        raise Unsupported(form(ins))

    # --- control flow ------------------------------------------------------

    def _branch(self, ins, op: str, local: set[int]) -> str:
        ops = ins.operands
        target_op = ops[-1]
        if op in ("b", "bl", "blx") and target_op.type == ca.ARM_OP_IMM:
            target = target_op.imm & 0xFFFFFFFF
            if op == "b":
                if (target & ~1) in local:
                    return f"goto L_{target & ~1:08x};"
                self.referenced.add(target & ~1)
                # A branch out of the function is a tail call: the callee
                # returns to our caller, which in C is exactly a call and a
                # return.
                return f"{self.name(target & ~1)}(c); return;"
            self.referenced.add(target & ~1)
            ret = ins.address + ins.size
            return (f"ARC_W(c, 14, {self.img(ret)}); "
                    f"{self.name(target & ~1)}(c);")
        if op in ("bx", "blx", "bxj") and target_op.type == ca.ARM_OP_REG:
            rm = self.reg(ins, target_op.reg)
            if op == "bx" and rm == 14:
                return "return;"
            value = self.read(ins, rm)
            if op == "blx":
                ret = ins.address + ins.size
                return f"ARC_W(c, 14, {self.img(ret)}); arc_dispatch(c, {value});"
            return f"arc_dispatch(c, {value}); return;"
        raise Unsupported(form(ins))

    # --- one instruction ---------------------------------------------------

    def instruction(self, ins, local: set[int]) -> str:
        op = self.root(ins)
        table = self.tables.get(ins.address)
        if table:
            # A resolved switch becomes the branch it always was. The guest's
            # own `cmp` is the bounds check, and the condition this load
            # carries is what lets an out-of-range selector fall through to
            # the default -- so the conditional wrapper at the end of this
            # function is exactly the right thing to leave it to.
            idx = self.reg(ins, ins.operands[1].mem.index)
            arms = " ".join(f"case {k}: goto L_{t:08x};"
                            for k, t in enumerate(table))
            body = f"switch (ARC_R(c, {idx})) {{ {arms} default: break; }}"
        elif op in ALU3:
            body = self._alu3(ins, op)
        elif op in ALU2:
            body = self._alu2(ins, op)
        elif op in TEST:
            body = self._test(ins, op)
        elif op in SHIFTOP:
            body = self._shift(ins, op)
        elif op in ("mul", "mla", "mls", "umull", "smull", "umlal", "smlal"):
            body = self._mul(ins, op)
        elif op in ("uxtb", "uxth", "sxtb", "sxth", "uxtab", "uxtah",
                    "sxtab", "sxtah"):
            body = self._extend(ins, op)
        elif op in ("b", "bl", "bx", "blx", "bxj"):
            body = self._branch(ins, op, local)
        elif op.startswith("ldr") and not op.startswith("ldrex"):
            body = self._load(ins, op)
        elif op.startswith("str") and not op.startswith("strex"):
            body = self._store(ins, op)
        elif op in ("push", "pop") or op.startswith(("ldm", "stm")):
            body = self._block(ins, op)
        elif op in ("smulbb", "smulbt", "smultb", "smultt"):
            body = self._smulxy(ins, op)
        elif op == "vmov":
            body = self._vmov(ins, op)
        elif op in ("vldr", "vstr"):
            body = self._vldst(ins, op)
        elif op in ("vpush", "vpop"):
            body = self._vblock(ins, op)
        elif op in ("vadd", "vsub", "vmul", "vdiv", "vnmul", "vmla", "vmls",
                    "vnmla",
                    "vnmls", "vneg", "vabs", "vsqrt"):
            body = self._vfp_arith(ins, op)
        elif op in ("vcmp", "vcmpe"):
            body = self._vcmp(ins, op)
        elif op == "vcvt":
            body = self._vcvt(ins, op)
        elif op == "vmrs":
            body = self._vmrs(ins, op)
        else:
            body = self._misc(ins, op)
        if ins.cc and ins.cc != ca.ARM_CC_AL:
            return f"if (ARC_COND_{CC_MACRO[ins.cc]}(c)) {{ {body} }}"
        return body

    # --- decode and reachability -------------------------------------------

    def decode(self, body: bytes, addr: int, thumb: bool) -> dict:
        """Every instruction in the range, by address.

        Capstone stops at the first byte it cannot decode, which in a
        symbol-delimited function is the literal pool at the end. Step past it
        and resume, so a pool in the middle does not hide the code after it.
        """
        md = self.md[thumb]
        out, pos, step = {}, 0, 2 if thumb else 4
        while pos < len(body):
            before = pos
            for ins in md.disasm(body[pos:], addr + pos):
                out[ins.address] = ins
                pos = ins.address - addr + ins.size
            if pos == before:
                pos += step
        return out

    def writes_pc(self, ins, op: str) -> bool:
        if op in ("b", "bx", "bxj"):
            return True
        if op in ("pop", "ldm", "ldmia", "ldmib", "ldmda", "ldmdb"):
            return any(o.type == ca.ARM_OP_REG and self.reg(ins, o.reg) == 15
                       for o in ins.operands)
        if op in ALU2 or op in ALU3 or op.startswith("ldr"):
            ops = ins.operands
            return bool(ops) and ops[0].type == ca.ARM_OP_REG \
                and self.reg(ins, ops[0].reg) == 15
        return False

    def jump_table(self, insns: dict, a: int):
        """Targets of `ldr<cond> pc, [pc, rN, lsl #2]` -- an ARM switch.

        A dense switch compiles to a bounds check, a load of the PC from a
        table indexed by the selector, and a fall-through to the default:

            cmp   r3, #4                  <- the bound, and the only record
            ldrls pc, [pc, r3, lsl #2]       of how long the table is
            b     <default>
            <5 words of absolute addresses>

        The table is read at lift time for exactly the reason a literal-pool
        load is folded at lift time: it lives in `__TEXT`, which is mapped r-x
        and cannot be written, and the image is never slid, so those words are
        already the addresses they will have at run time.

        Without this the walk stops at the load. The table is data, so nothing
        branches to the case bodies, they are never reached, and they lift to
        nothing -- then the switch becomes an indirect branch to an address
        that is inside a function but is not its entry, which the dispatcher
        cannot answer. Two thirds of `-[Shard init]` was invisible this way,
        and it is the function `PlayState` faults in.

        Returns None rather than guessing whenever anything does not fit.
        """
        ins = insns[a]
        ops = ins.operands
        if len(ops) != 2 or ops[0].type != ca.ARM_OP_REG:
            return None
        if self.reg(ins, ops[0].reg) != 15 or ops[1].type != ca.ARM_OP_MEM:
            return None
        mem = ops[1].mem
        if not mem.base or self.reg(ins, mem.base) != 15 or not mem.index:
            return None
        if ops[1].shift.value != 2:        # a table of words, scaled by 4
            return None
        idx = self.reg(ins, mem.index)

        # The bound lives in the compare that set the condition this load is
        # predicated on. An unconditional load of the PC has no bound at all
        # and there is nothing here to find.
        if not ins.cc or ins.cc == ca.ARM_CC_AL:
            return None
        count, b = None, a - ins.size
        for _ in range(4):
            if b not in insns:
                break
            prev = insns[b]
            pops = prev.operands
            if prev.mnemonic.split(".")[0] == "cmp" and len(pops) == 2 \
                    and pops[0].type == ca.ARM_OP_REG \
                    and self.reg(prev, pops[0].reg) == idx \
                    and pops[1].type == ca.ARM_OP_IMM:
                count = pops[1].imm + 1
                break
            b -= prev.size
        if not count or count < 1 or count > 4096:
            return None

        base = a + 8                       # the ARM PC bias, not a guess
        out = []
        for k in range(count):
            word = self.literal(base + k * 4, 4)
            # Every entry has to be an instruction in this same function. A
            # word that is not says the bound was wrong, and a wrong bound
            # means reading whatever follows the table as addresses.
            if word is None or (word & 0xFFFFFFFE) not in insns:
                return None
            out.append(word & 0xFFFFFFFE)
        return out

    def reachable(self, insns: dict, start: int) -> set[int]:
        """Walk from the entry point.

        This is what separates code from the literal pool. A pool sits past an
        unconditional terminator with nothing branching into it, so it is simply
        never reached -- no heuristic about what a word of zeroes means.
        """
        seen: set[int] = set()
        self.tables = {}
        work = [start]
        while work:
            a = work.pop()
            if a in seen or a not in insns:
                continue
            seen.add(a)
            ins = insns[a]
            try:
                op = self.root(ins)
                ends = self.writes_pc(ins, op)
            except Unsupported:
                op, ends = "", False
            if op in ("b", "bl", "blx") and ins.operands \
                    and ins.operands[-1].type == ca.ARM_OP_IMM:
                t = ins.operands[-1].imm & 0xFFFFFFFE
                if t in insns:
                    work.append(t)
            # A switch reaches its case bodies only through the table.
            if ends and op == "ldr" and a not in self.tables:
                table = self.jump_table(insns, a)
                if table:
                    self.tables[a] = table
                    work.extend(table)
            # A conditional terminator still falls through to the next
            # instruction; only an unconditional one ends the run.
            if not (ends and (not ins.cc or ins.cc == ca.ARM_CC_AL)):
                work.append(a + ins.size)
        return seen

    # --- one function ------------------------------------------------------

    def lift_function(self, addr: int, size: int, body: bytes,
                      thumb: bool) -> tuple[str, bool]:
        self.thumb = thumb
        insns = self.decode(body, addr, thumb)
        live = self.reachable(insns, addr)
        order = sorted(live)

        targets: set[int] = set()
        for a in order:
            ins = insns[a]
            try:
                op = self.root(ins)
            except Unsupported:
                continue
            if op == "b" and ins.operands and ins.operands[-1].type == ca.ARM_OP_IMM:
                t = ins.operands[-1].imm & 0xFFFFFFFE
                if t in live:
                    targets.add(t)
            # Every case body of a resolved switch is jumped to by label.
            for t in self.tables.get(a, ()):
                if t in live:
                    targets.add(t)

        lines = [f"/* {self.name(addr)}: {len(order)} instructions, "
                 f"{'thumb' if thumb else 'arm'} */",
                 f"void {self.name(addr)}(Arm32Ctx* c) {{",
                 # A ring of which guest functions were entered. It costs one
                 # store per call and only exists under ARC_FRAMES, and it is
                 # the only backtrace there is: the host stack is tens of
                 # thousands of identically shaped C functions, and a fault
                 # names the data it touched rather than the code that touched
                 # it. A ring rather than a stack, so no return path can miss
                 # a pop and there is nothing to keep balanced.
                 f"  arc_frame_note({addr:#010x}u);"]
        complete = True
        for i, a in enumerate(order):
            ins = insns[a]
            self.insns_total += 1
            if a in targets:
                lines.append(f"L_{a:08x}:;")
            text = f"{ins.mnemonic} {ins.op_str}".strip()
            try:
                code = self.instruction(ins, live)
                self.insns_lifted += 1
            except Unsupported as why:
                key = str(why)
                self.unsupported[key] += 1
                if complete:
                    self.blamed[key] += 1
                complete = False
                code = f'arc_trap(c, "{self.name(addr)}: {text}");'
            lines.append(f"  /* {a:08x}  {text} */")
            lines.append(f"  {code}")
            # Reachable code is not always contiguous: a pool can sit between
            # two live runs. Falling off the end of one into the other would be
            # silently wrong, so the gap is jumped explicitly.
            nxt = order[i + 1] if i + 1 < len(order) else None
            if nxt is not None and nxt != a + ins.size:
                lines.append(f"  goto L_{nxt:08x};")
                targets.add(nxt)
        lines.append("}")
        # A label the gap jump introduced late still has to exist.
        out = "\n".join(lines)
        for t in targets:
            if f"L_{t:08x}:;" not in out:
                out = out.replace(f"  /* {t:08x}  ", f"L_{t:08x}:;\n  /* {t:08x}  ", 1)
        return out, complete


def mapped_image(path: str, want: str = "") -> tuple[int, bytes]:
    """(link base, the image as the loader would lay it out).

    Every segment with file content, at its own vmaddr, in one buffer -- not
    just __text. A function reaching a global reads __DATA, and a harness that
    maps only the code section reports that as a wild pointer.
    """
    _, data, _ = probe.read_app(path)
    ms, _ = probe.slices(data)
    m = ms[0]
    if want:
        for s in ms:
            if probe.ARM_SUBTYPE.get(s.cpusubtype & 0xFF) == want:
                m = s
                break
    segs = [s for s in m.segments if s[2] and s[0] != "__PAGEZERO"]
    base = min(s[1] for s in segs)
    span = max(s[1] + s[2] for s in segs) - base
    out = bytearray(span)
    for name, vmaddr, vmsize, fileoff, filesize, _ in segs:
        if filesize:
            out[vmaddr - base:vmaddr - base + filesize] = \
                data[m.off + fileoff:m.off + fileoff + filesize]
    return base, bytes(out)


def load(path: str, want: str = ""):
    """(link_base, text_addr, text_bytes, functions) for one binary."""
    exe, data, _ = probe.read_app(path)
    ms, _ = probe.slices(data)
    if not ms:
        sys.exit("no 32-bit ARM slice")
    m = ms[0]
    if want:
        for s in ms:
            if probe.ARM_SUBTYPE.get(s.cpusubtype & 0xFF) == want:
                m = s
                break
    if m.encryption and m.encryption[2]:
        sys.exit("__TEXT is FairPlay-encrypted; the lifter would be reading noise")
    addr, code = m.text()
    # __PAGEZERO sits at address 0 with a real size, so a naive minimum
    # over the segments makes the link base 0 and every emitted offset
    # silently absolute. The base that matters is where the first mapped
    # segment actually goes.
    link_base = min(s[1] for s in m.segments
                    if s[2] and s[0] != "__PAGEZERO")
    return exe, link_base, addr, code, probe.functions(m)


def read_only_span(path: str, want: str = "") -> tuple[int, int]:
    """The address range a literal fold is allowed to read from.

    __TEXT only. It is the segment mapped r-x, so nothing in the program can
    write it, which is the property the fold depends on.
    """
    _, data, _ = probe.read_app(path)
    ms, _ = probe.slices(data)
    m = ms[0]
    if want:
        for s in ms:
            if probe.ARM_SUBTYPE.get(s.cpusubtype & 0xFF) == want:
                m = s
                break
    for name, vmaddr, vmsize, _, filesize, _ in m.segments:
        if name == "__TEXT":
            return vmaddr, vmaddr + min(vmsize, filesize)
    return (0, 0)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary", help=".ipa, .app directory, or a bare Mach-O")
    ap.add_argument("--slice", default="", help="armv6 or armv7")
    ap.add_argument("--out", help="write the lifted program here")
    ap.add_argument("--report", action="store_true",
                    help="what is still missing, worst first")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--shards", type=int, default=8)
    args = ap.parse_args()

    exe, link_base, text_addr, code, fns = load(args.binary, args.slice)
    lifter = Lifter()
    lifter.link_base = link_base
    lifter.starts = {a for a, _, _ in fns}
    _, lifter.image = mapped_image(args.binary, args.slice)
    lifter.ro_range = read_only_span(args.binary, args.slice)

    print(f"{exe}: {len(fns):,} functions, __text {len(code) / 1e6:.2f} MB "
          f"@ {text_addr:#x}, link base {link_base:#x}")

    bodies, done = [], 0
    for a, size, thumb in fns:
        if args.limit and done >= args.limit:
            break
        done += 1
        chunk = code[a - text_addr:a - text_addr + size]
        source, complete = lifter.lift_function(a, size, chunk, thumb)
        bodies.append((a, source, complete))

    complete = sum(1 for _, _, ok in bodies if ok)
    pct_fn = 100.0 * complete / len(bodies) if bodies else 0.0
    pct_in = 100.0 * lifter.insns_lifted / lifter.insns_total \
        if lifter.insns_total else 0.0
    print(f"\nfunctions complete : {complete:,} / {len(bodies):,}  ({pct_fn:.1f}%)")
    print(f"instructions lifted: {lifter.insns_lifted:,} / "
          f"{lifter.insns_total:,}  ({pct_in:.1f}%)")
    print(f"literals folded    : {lifter.folded:,}  "
          f"(reads of __TEXT resolved at lift time, so none remain at run time)")

    if args.report and lifter.blamed:
        print("\nby functions broken -- what to write next:")
        print(f"  {'form':<34} {'fns':>6} {'insns':>8}")
        for key, n in lifter.blamed.most_common(25):
            print(f"  {key:<34} {n:>6,} {lifter.unsupported[key]:>8,}")
        rest = len(lifter.unsupported) - 25
        if rest > 0:
            print(f"  ... and {rest} more forms")

    if args.out:
        emit_program(lifter, bodies, args.out, args.shards)


def emit_program(lifter: Lifter, bodies, out_dir: str, shards: int) -> None:
    os.makedirs(out_dir, exist_ok=True)
    defined = {a for a, _, _ in bodies}
    stubs = sorted(lifter.referenced - defined)
    handles = [open(os.path.join(out_dir, f"lifted_{i:03d}.c"), "w",
                    encoding="utf-8") for i in range(shards)]
    for fh in handles:
        fh.write('#include "lifted.h"\n\n')
    for i, (_, source, _) in enumerate(bodies):
        handles[i % shards].write(source + "\n\n")
    for fh in handles:
        fh.close()

    with open(os.path.join(out_dir, "stubs.c"), "w", encoding="utf-8") as fh:
        fh.write('#include "lifted.h"\n\n')
        fh.write("// A branch target with no lifted body. Most of these are\n"
                 "// import stubs -- objc_msgSend, malloc, glDrawArrays -- so\n"
                 "// they go through the runtime's native table first and trap\n"
                 "// only if nothing claimed them. Trapping here unconditionally\n"
                 "// would make every import unreachable by construction.\n")
        for a in stubs:
            fh.write(f'void {Lifter.name(a)}(Arm32Ctx* c) {{ '
                     f'arc_dispatch_miss(c, {a:#010x}u); }}\n')

    every = sorted(defined | set(stubs))
    with open(os.path.join(out_dir, "lifted.h"), "w", encoding="utf-8") as fh:
        fh.write("// Generated by tools/lifter.py -- do not edit.\n"
                 '#pragma once\n#include "arm32_context.h"\n\n'
                 '#ifdef __cplusplus\nextern "C" {\n#endif\n\n'
                 "void arc_install_lifted(uint32_t image_base);\n\n")
        for a in every:
            fh.write(f"void {Lifter.name(a)}(Arm32Ctx*);\n")
        fh.write('\n#ifdef __cplusplus\n}\n#endif\n')

    with open(os.path.join(out_dir, "dispatch.c"), "w", encoding="utf-8") as fh:
        fh.write('#include "lifted.h"\n\n'
                 "typedef void (*ArcFn)(Arm32Ctx*);\n"
                 "typedef struct { uint32_t addr; ArcFn fn; } ArcEntry;\n\n"
                 "// Sorted by address so the lookup is a bisection. Keyed on\n"
                 "// the *masked* address: the Thumb bit is a mode selector,\n"
                 "// not part of any address.\n"
                 "static const ArcEntry kTable[] = {\n")
        for a in every:
            # Keyed on the offset from the image base, not the absolute
            # link-time address the function name is built from.
            fh.write(f"  {{ {a - lifter.link_base:#010x}u, "
                     f"{Lifter.name(a)} }},\n")
        fh.write("};\n\n"
                 f"#define ARC_TABLE_COUNT {len(every)}\n\n")
        fh.write("""static uint32_t g_base;

static void arc_dispatch_lifted(Arm32Ctx* c, uint32_t target) {
  const uint32_t addr = ARC_CODE_ADDR(target) - g_base;
  size_t lo = 0, hi = ARC_TABLE_COUNT;
  while (lo < hi) {
    const size_t mid = lo + (hi - lo) / 2;
    if (kTable[mid].addr < addr) lo = mid + 1;
    else hi = mid;
  }
  if (lo < ARC_TABLE_COUNT && kTable[lo].addr == addr) {
    kTable[lo].fn(c);
    return;
  }
  // Not lifted code. It may be a host import the guest reached through its
  // stub, which the runtime knows about and this table does not.
  arc_dispatch_miss(c, target);
}

void arc_install_lifted(uint32_t image_base) {
  g_base = image_base;
  arc_set_dispatch(arc_dispatch_lifted);
}
""")

    total = sum(os.path.getsize(os.path.join(out_dir, f))
                for f in os.listdir(out_dir))
    print(f"\nwrote {out_dir}: {len(defined):,} functions, {len(stubs):,} stubs "
          f"across {shards} units ({total / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
