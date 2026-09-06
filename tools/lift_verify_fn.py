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

A function is tested when its *whole call tree* is lifted. Both sides then run
the same code -- the oracle by executing the callee's instructions, the lifted
side by calling the C function it became -- so a direct call is no obstacle.
What still cannot be followed is anything that leaves: an indirect branch, a
call to something never lifted, or an instruction with no emitter. There the
two sides would be comparing a trap to a fault.

That distinction matters more than it sounds. Restricting this to functions
that call *nothing* covered 150 of Canabalt's 626, and left every argument
forwarder, every initialiser and every wrapper untested -- which is where a
lifting bug has the most room to hide.
"""
from __future__ import annotations

import argparse
import glob
import re
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
    from unicorn import UC_PROT_ALL, UC_HOOK_CODE
    from unicorn import arm_const as uc
except ImportError as e:
    sys.exit(f"need unicorn: pip install unicorn ({e})")

# Where a returning function lands. Mapped, so that reaching it is a stop
# rather than a fetch fault that has to be told apart from a real one.
SENTINEL = 0x50000000
# A runaway function must end the case, not the run.
MAX_STEPS = 2_000_000


def survey(lf: L.Lifter, code: bytes, text_addr: int, fns):
    """{address: (functions it calls, whether it leaves the lifted world)}.

    A direct call is fine to test through: both sides run the same code, the
    oracle by executing it and the lifted side by calling the C function. What
    cannot be followed is anything that leaves -- an indirect branch, a call to
    a target that was never lifted, a supervisor call, or an instruction with
    no emitter. `bx lr` and a stack pop into PC are returns and stay.
    """
    out = {}
    for a, size, thumb in fns:
        lf.thumb = thumb
        insns = lf.decode(code[a - text_addr:a - text_addr + size], a, thumb)
        live = lf.reachable(insns, a)
        calls, escapes = set(), not live
        for adr in sorted(live):
            ins = insns[adr]
            try:
                body = lf.instruction(ins, live)
            except L.Unsupported:
                escapes = True
                break
            if "arc_dispatch" in body or "arc_trap" in body:
                escapes = True
                break
            for m in re.finditer(r"fn_([0-9a-f]{8})\(c\)", body):
                calls.add(int(m.group(1), 16))
        out[a] = (calls, escapes)
    return out


def testable(info: dict, defined: set[int], stubs: set[int],
             start: int) -> bool:
    """Whether a function's whole call tree can be run on both sides.

    This is what takes the harness past leaf functions. A caller is only
    testable if everything it reaches is: one unlifted callee anywhere in the
    tree and the two sides diverge at it, the oracle executing the real
    instructions while the lifted side traps.
    """
    seen, work = set(), [start]
    while work:
        a = work.pop()
        if a in seen:
            continue
        seen.add(a)
        if a in stubs:
            # An import, neutralised identically on both sides. Not something
            # to follow, and no longer a reason to skip the caller.
            continue
        if a not in info or a not in defined:
            return False
        calls, escapes = info[a]
        if escapes:
            return False
        work.extend(calls)
    return True


def pick(lf: L.Lifter, code: bytes, text_addr: int, fns, count: int,
         available: set[int], stubs: set[int], rng: random.Random,
         leaves_only: bool = False):
    info = survey(lf, code, text_addr, fns)
    ok, leaf = [], 0
    for a, size, thumb in fns:
        if a not in available or not testable(info, available, stubs, a):
            continue
        if not info[a][0]:
            leaf += 1
        elif leaves_only:
            continue
        ok.append((a, size, thumb))
    print(f"  {len(ok):,} testable of {len(fns):,}: {leaf:,} call nothing, "
          f"{len(ok) - leaf:,} have a fully lifted call tree")
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
               image, image_size, link_base, stubs=frozenset()):
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
    # The oracle's half of the same bargain: reaching a stub sets r0 and
    # returns, exactly as the lifted side's registered native does. Without
    # this the emulator would execute the stub's real instructions, which
    # branch through a pointer dyld was supposed to fill in.
    if stubs:
        lo, hi = min(stubs), max(stubs) + 4

        def leave(engine, address, size, _):
            if address in stubs:
                engine.reg_write(uc.UC_ARM_REG_R0, 0)
                engine.reg_write(uc.UC_ARM_REG_PC,
                                 engine.reg_read(uc.UC_ARM_REG_LR))

        mu.hook_add(UC_HOOK_CODE, leave, begin=lo, end=hi)

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
    ap.add_argument("--leaves-only", action="store_true",
                    help="only functions that call nothing, as before")
    args = ap.parse_args()

    exe_name, link_base, text_addr, code, fns = L.load(args.binary, args.slice)
    lf = L.Lifter()
    lf.link_base = link_base
    V.LINK_BASE = link_base

    defined = generated_functions(args.generated)
    rng = random.Random(args.seed)
    starts = {a for a, _, _ in fns}
    stubs = defined - starts
    chosen = pick(lf, code, text_addr, fns, args.count, defined, stubs, rng,
                  args.leaves_only)
    if not chosen:
        sys.exit("no self-contained functions to test")
    print(f"{exe_name}: testing {len(chosen):,} functions, "
          f"{args.seeds} states each")

    # Every mapped segment, at its own vmaddr, exactly as the
    # loader would lay it out -- a function reaching a global
    # reads __DATA, and mapping only the code section reports
    # that as a wild pointer.
    V.IMAGE_BASE = link_base
    _, image_full = L.mapped_image(args.binary, args.slice)
    image_size = V.align_up(V.IMAGE_BASE + len(image_full)) - V.IMAGE_BASE
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
                            link_base, stubs)
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
        fh.write(image_full[V.IMAGE_FLOOR - V.IMAGE_BASE:])
        ordered = sorted(stubs)
        fh.write(struct.pack("<I", len(ordered)))
        for at in ordered:
            fh.write(struct.pack("<I", at))
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
