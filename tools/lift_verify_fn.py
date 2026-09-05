#!/usr/bin/env python3
"""Differential-test whole lifted functions against Unicorn.

`lift_verify.py` checks one instruction at a time, which deliberately excludes
control flow. This checks entire functions: the branches, the `goto` web a
lifted function turns into, and the register and memory state that survives
across them.

The difference is not academic. A form keyed on mnemonic and operand shapes
does not record whether a load's base register is also one of its
destinations, so the per-instruction harness can only find that class of bug by
luck. Neither can it check the decisions the lifter makes *about* a function --
that `pop {r4, pc}` is a return rather than an indirect branch, that a literal
pool in the middle of a function is data, or that a run of reachable code
jumped over one lands where it should.

    python tools/lift_verify_fn.py Canabalt.ipa --generated ../canabaltrecomp/generated
    python tools/lift_verify_fn.py Canabalt.ipa --generated gen/ --count 120

Only self-contained functions are tested. A call would run arbitrarily deep and
reach an unlifted stub, and an indirect branch has nothing to resolve against
here, so both sides would be comparing a trap to a fault.
"""
from __future__ import annotations

import argparse
import glob
import os
import random
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lifter as L  # noqa: E402
import lift_verify as V  # noqa: E402

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UcError
    from unicorn import UC_PROT_ALL
    from unicorn import arm_const as uc
except ImportError as e:
    sys.exit(f"need unicorn: pip install unicorn ({e})")

# Where a returning function lands. Mapped, so that reaching it is a stop
# rather than a fetch fault that has to be told apart from a real one.
SENTINEL = 0x50000000
# A runaway function must end the case, not the run.
MAX_STEPS = 200_000


def self_contained(lf: L.Lifter, addr: int, size: int, body: bytes,
                   thumb: bool) -> bool:
    """Whether a function can be run in isolation.

    Anything that leaves -- a call, an indirect branch, a supervisor call --
    takes the test somewhere neither side can follow. `bx lr` and a stack pop
    into PC are returns and stay.
    """
    lf.thumb = thumb
    insns = lf.decode(body, addr, thumb)
    live = lf.reachable(insns, addr)
    if not live:
        return False
    for a in sorted(live):
        ins = insns[a]
        try:
            code = lf.instruction(ins, live)
        except L.Unsupported:
            return False
        if "fn_" in code or "arc_dispatch" in code or "arc_trap" in code:
            return False
    return True


def pick(lf: L.Lifter, code: bytes, text_addr: int, fns, count: int,
         available: set[int], rng: random.Random):
    ok = []
    for a, size, thumb in fns:
        if a not in available:
            continue
        chunk = code[a - text_addr:a - text_addr + size]
        if self_contained(lf, a, size, chunk, thumb):
            ok.append((a, size, thumb))
    rng.shuffle(ok)
    return ok[:count] if count else ok


def generated_functions(generated: str) -> set[int]:
    """Which addresses the generated program actually defines."""
    out: set[int] = set()
    header = os.path.join(generated, "lifted.h")
    if not os.path.exists(header):
        sys.exit(f"no lifted.h in {generated} -- run the lifter with --out first")
    for line in open(header, encoding="utf-8"):
        if line.startswith("void fn_") and "(Arm32Ctx*)" in line:
            out.add(int(line[len("void fn_"):line.index("(")], 16))
    return out


def run_oracle(addr: int, thumb: bool, regs, flags, vec, fpscr, scratch,
               image, image_size, link_base):
    """Unicorn's answer for a whole function, or None if it did not return.

    A function that faults or runs away is not a fair comparison: the lifted
    side would be asked to reproduce something that never finished.
    """
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB if thumb else UC_MODE_ARM)
    try:
        cpacr = mu.reg_read(uc.UC_ARM_REG_C1_C0_2)
        mu.reg_write(uc.UC_ARM_REG_C1_C0_2, cpacr | (0xF << 20))
        mu.reg_write(uc.UC_ARM_REG_FPEXC, 0x40000000)
    except UcError:
        pass
    mu.mem_map(V.IMAGE_BASE, image_size, UC_PROT_ALL)
    mu.mem_write(V.IMAGE_BASE, image)
    mu.mem_map(V.SCRATCH_BASE, V.SCRATCH_SIZE, UC_PROT_ALL)
    mu.mem_write(V.SCRATCH_BASE, scratch)
    mu.mem_map(SENTINEL, 0x1000, UC_PROT_ALL)
    for i, r in enumerate(V.UC_R):
        mu.reg_write(r, regs[i])
    # The return address is the sentinel on both sides: the lifted function
    # returns to its C caller, and this is the equivalent place to stop.
    mu.reg_write(uc.UC_ARM_REG_LR, SENTINEL)
    nf, zf, cf, vf = flags
    cpsr = mu.reg_read(uc.UC_ARM_REG_CPSR) & ~0xF0000000
    cpsr |= (nf << 31) | (zf << 30) | (cf << 29) | (vf << 28)
    mu.reg_write(uc.UC_ARM_REG_CPSR, cpsr)
    for i, sreg in enumerate(V.UC_S):
        mu.reg_write(sreg, (vec[i // 2] >> (32 * (i % 2))) & 0xFFFFFFFF)
    mu.reg_write(uc.UC_ARM_REG_FPSCR, fpscr)
    entry = V.IMAGE_BASE + (addr - link_base)
    try:
        mu.emu_start(entry | (1 if thumb else 0), SENTINEL, count=MAX_STEPS)
    except UcError:
        return None
    if mu.reg_read(uc.UC_ARM_REG_PC) & ~1 != SENTINEL:
        return None  # ran out of steps rather than returning
    out_regs = [mu.reg_read(r) for r in V.UC_R] + [0]
    cpsr = mu.reg_read(uc.UC_ARM_REG_CPSR)
    out_flags = ((cpsr >> 31) & 1, (cpsr >> 30) & 1, (cpsr >> 29) & 1,
                 (cpsr >> 28) & 1)
    singles = [mu.reg_read(s) & 0xFFFFFFFF for s in V.UC_S]
    out_vec = [singles[2 * i] | (singles[2 * i + 1] << 32) for i in range(16)]
    out_vec += list(vec[16:])
    return (out_regs, out_flags, out_vec,
            mu.mem_read(V.SCRATCH_BASE, V.SCRATCH_SIZE),
            mu.mem_read(V.IMAGE_BASE, image_size))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary")
    ap.add_argument("--generated", required=True,
                    help="the directory the lifter wrote")
    ap.add_argument("--slice", default="")
    ap.add_argument("--count", type=int, default=150,
                    help="how many self-contained functions to test")
    ap.add_argument("--seeds", type=int, default=6, help="states per function")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    exe_name, link_base, text_addr, code, fns = L.load(args.binary, args.slice)
    lf = L.Lifter()
    lf.link_base = link_base
    V.LINK_BASE = link_base

    defined = generated_functions(args.generated)
    rng = random.Random(args.seed)
    chosen = pick(lf, code, text_addr, fns, args.count, defined, rng)
    if not chosen:
        sys.exit("no self-contained functions to test")
    print(f"{exe_name}: {len(chosen):,} self-contained functions of "
          f"{len(fns):,}, {args.seeds} states each")

    # Every mapped segment, at its own vmaddr, exactly as the
    # loader would lay it out -- a function reaching a global
    # reads __DATA, and mapping only the code section reports
    # that as a wild pointer.
    _, image_full = L.mapped_image(args.binary, args.slice)
    image_size = V.align_up(len(image_full))
    image_full = image_full.ljust(image_size, b"\0")

    # Each case is a call into the already-generated program, so the emitter
    # under test is the one a build would actually use -- not a re-emission
    # that could drift from it.
    V.EXTRA_HEADERS = ["lifted.h"]
    trials = [(a, thumb, s) for (a, _, thumb) in chosen
              for s in range(args.seeds)]
    cases = [V.Case(a, 4, L.Lifter.name(a), L.Lifter.name(a),
                    f"{L.Lifter.name(a)}(c);", thumb)
             for a, thumb, _ in trials]

    workdir = tempfile.mkdtemp(prefix="arcverifyfn-")
    sources = sorted(glob.glob(os.path.join(args.generated, "*.c")))
    exe = V.build_driver(cases, image_full, workdir,
                         extra_sources=sources,
                         extra_includes=[os.path.abspath(args.generated)])
    ctx_size = int(subprocess.run([exe, "--size"], capture_output=True,
                                  text=True).stdout.strip())

    states, expected, live = [], [], []
    for (a, thumb, s), case in zip(trials, cases):
        st = V.seed(rng, pointerish=True)
        # Both sides must start with the same return address. The lifted
        # function returns to its C caller and the oracle stops at the
        # sentinel, but a function that never touches lr still leaves it in
        # place, and comparing a seeded value against the sentinel would
        # report every such function as wrong.
        st[0][14] = SENTINEL
        oracle = run_oracle(a, thumb, *st[:4], st[4], image_full, image_size,
                            link_base)
        if oracle is None:
            continue
        live.append(case)
        states.append(st)
        expected.append(oracle)

    if not live:
        sys.exit("no function returned cleanly in the oracle")

    exe = V.build_driver(live, image_full, workdir,
                         extra_sources=sources,
                         extra_includes=[os.path.abspath(args.generated)])
    in_path, out_path = (os.path.join(workdir, "in.bin"),
                         os.path.join(workdir, "out.bin"))
    with open(in_path, "wb") as fh:
        fh.write(image_full)
        for (regs, flags, vec, fpscr, scratch) in states:
            fh.write(V.pack_ctx(regs, flags, vec, fpscr, ctx_size))
            fh.write(scratch)
    subprocess.run([exe, in_path, out_path], capture_output=True)

    blob = open(out_path, "rb").read()
    stride = 4 + ctx_size + V.SCRATCH_SIZE
    ran = len(blob) // stride
    if ran < len(live):
        print(f"\nthe lifted side stopped after {ran} of {len(live)} cases -- "
              f"it faulted in {live[ran].text}")

    bad, examples = {}, {}
    for i in range(ran):
        got = blob[i * stride:(i + 1) * stride]
        status = struct.unpack_from("<I", got, 0)[0]
        regs, flags, vec, _ = V.unpack_ctx(got[4:4 + ctx_size])
        mem = got[4 + ctx_size:]
        exp_regs, exp_flags, exp_vec, exp_mem, _ = expected[i]
        why = "trapped in lifted code" if status else None
        # The callee-saved registers and the stack pointer are what a caller
        # relies on; r0-r3 and r12 are scratch under the ABI but are compared
        # too, because a difference there is still a difference.
        if why is None:
            for n in range(15):
                if regs[n] != exp_regs[n]:
                    why = f"r{n} = {regs[n]:#x}, expected {exp_regs[n]:#x}"
                    break
        if why is None and tuple(flags[:4]) != tuple(exp_flags):
            why = (f"flags nzcv = {''.join(str(x) for x in flags[:4])}, "
                   f"expected {''.join(str(x) for x in exp_flags)}")
        if why is None:
            for n in range(16):
                if vec[n] != exp_vec[n]:
                    why = f"d{n} = {vec[n]:#x}, expected {exp_vec[n]:#x}"
                    break
        if why is None and bytes(mem) != bytes(exp_mem):
            off = next(k for k in range(V.SCRATCH_SIZE)
                       if mem[k] != exp_mem[k])
            why = f"memory at scratch+{off:#x}"
        if why:
            bad[live[i].text] = bad.get(live[i].text, 0) + 1
            examples.setdefault(live[i].text, why)

    ok = ran - sum(bad.values())
    print(f"\nagreed: {ok:,} / {ran:,}  ({100.0 * ok / ran:.2f}%)   "
          f"over {len({c.text for c in live[:ran]}):,} functions")
    if bad:
        print("\ndisagreements, worst first:")
        for name, n in sorted(bad.items(), key=lambda kv: -kv[1])[:30]:
            print(f"  {name:<18} {n:>4}  {examples[name]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
