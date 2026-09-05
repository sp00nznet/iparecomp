#!/usr/bin/env python3
"""Differential-test one lifted instruction at a time against Unicorn.

The property that makes this worth doing is that Unicorn is an *independent*
implementation. A misreading invented in the emitters -- a carry taken from the
ALU when it should have come from the shifter, a PC read off by four -- is not
mirrored in it, so the two disagree and say so. Checking the emitters against
capstone would not have that property: capstone is where they get their
operands from.

The instructions are harvested from a real binary rather than synthesised. Real
code exercises the operand shapes a compiler actually emits, in the proportions
it emits them, and none of the ones it never does.

    python tools/lift_verify.py Canabalt.ipa
    python tools/lift_verify.py Canabalt.ipa --per-form 24 --form "ldr"

Both sides see the image mapped at the same address, so a literal-pool load
reads the same bytes in each. Control flow is excluded here by construction --
that is what the whole-function harness is for.
"""
from __future__ import annotations

import argparse
import collections
import os
import random
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lifter as L  # noqa: E402

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UcError
    from unicorn import UC_PROT_ALL
    from unicorn import arm_const as uc
except ImportError as e:
    sys.exit(f"need unicorn: pip install unicorn ({e})")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Windows will not map the first 64 KB, and these images are linked at 0x1000,
# so the image cannot go at its own address on this host. That is exactly what
# `image_base` is for: both sides are told the same slid base and every
# PC-derived constant follows it.
IMAGE_BASE = 0x20000000
SCRATCH_BASE = 0x30000000
SCRATCH_SIZE = 0x4000
# Registers point at the middle, so an offset of either sign stays inside.
SCRATCH_MID = SCRATCH_BASE + SCRATCH_SIZE // 2

PAGE = 0x1000

UC_R = [getattr(uc, f"UC_ARM_REG_R{i}") for i in range(13)] + [
    uc.UC_ARM_REG_SP, uc.UC_ARM_REG_LR]
UC_S = [getattr(uc, f"UC_ARM_REG_S{i}") for i in range(32)]


def align_up(v: int, n: int = PAGE) -> int:
    return (v + n - 1) & ~(n - 1)


class Case:
    __slots__ = ("addr", "size", "text", "form", "body", "thumb")

    def __init__(self, addr, size, text, form, body, thumb):
        self.addr, self.size, self.text = addr, size, text
        self.form, self.body, self.thumb = form, body, thumb


def harvest(lf: L.Lifter, code: bytes, text_addr: int, fns, per_form: int,
            only: str) -> list[Case]:
    """Distinct real encodings, grouped by operand shape.

    Anything whose lifted body carries control flow is excluded: a branch would
    take the test outside the one instruction under examination, and there is
    nothing there to run.
    """
    picked: collections.defaultdict = collections.defaultdict(list)
    for a, size, thumb in fns:
        lf.thumb = thumb
        insns = lf.decode(code[a - text_addr:a - text_addr + size], a, thumb)
        live = lf.reachable(insns, a)
        for addr in sorted(live):
            ins = insns[addr]
            key = L.form(ins)
            if only and only not in key:
                continue
            if len(picked[key]) >= per_form:
                continue
            try:
                body = lf.instruction(ins, live)
            except L.Unsupported:
                continue
            # A direct call lifts to `fn_xxxxxxxx(c)`, which carries none of
            # the other markers and would leave an undefined symbol behind.
            if any(t in body for t in ("arc_dispatch", "return;", "goto ",
                                       "arc_trap", "fn_")):
                continue
            text = f"{ins.mnemonic} {ins.op_str}".strip()
            picked[key].append(Case(addr, ins.size, text, key, body, thumb))
    return [c for group in picked.values() for c in group]


CTX_FIELDS = 16 + 5           # r[16] then nf zf cf vf qf
CTX_STRUCT = "<21I3x"


def build_driver(cases: list[Case], image: bytes, workdir: str) -> str:
    """Compile every case into one program, run once per invocation.

    One process for the whole run rather than one per case: a lifted
    instruction that computes the wrong address faults, and a fault must name
    the case that caused it. Results are flushed as they are produced, so the
    last line in the file is the case that died.
    """
    src = os.path.join(workdir, "cases.c")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write('#include "arm32_context.h"\n')
        fh.write("#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n")
        fh.write("#ifdef _WIN32\n#include <windows.h>\n#else\n"
                 "#include <sys/mman.h>\n#endif\n\n")
        for i, c in enumerate(cases):
            fh.write(f"/* {c.text} */\n"
                     f"static void case_{i}(Arm32Ctx* c) {{ {c.body} }}\n")
        fh.write("\ntypedef void (*CaseFn)(Arm32Ctx*);\n"
                 "static CaseFn kCases[] = {\n")
        for i in range(len(cases)):
            fh.write(f"  case_{i},\n")
        fh.write("};\n")
        fh.write(DRIVER_MAIN.replace("@COUNT@", str(len(cases)))
                 .replace("@IMAGE_BASE@", hex(IMAGE_BASE))
                 .replace("@SCRATCH_BASE@", hex(SCRATCH_BASE))
                 .replace("@SCRATCH_SIZE@", hex(SCRATCH_SIZE))
                 .replace("@IMAGE_SIZE@", hex(align_up(len(image)))))
    exe = os.path.join(workdir, "cases.exe")
    cc = os.environ.get("CC", "gcc")
    cmd = [cc, "-O1", "-std=c11", "-I", os.path.join(ROOT, "runtime"),
           src, os.path.join(ROOT, "runtime", "arm32_runtime.c"), "-o", exe]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"compiling the cases failed:\n{r.stderr[:4000]}")
    return exe


DRIVER_MAIN = r"""
/* Reserve a region at exactly `at`, with an unmapped guard on either side.

   Scratch carved out of the interpreter's own heap turns an overrun into heap
   corruption, which kills the run and reports nothing. A guard turns the same
   overrun into a fault at the address that caused it.

   The guard has to be 64 KB on Windows, not one page. VirtualAlloc rounds a
   reservation base *down* to the 64 KB allocation granularity and succeeds, so
   asking for a guard one page below a 64 KB-aligned address silently returns a
   region 60 KB lower than requested -- and every guest address then reads real
   data from the wrong offset, which looks exactly like an emitter bug. Reserve
   the whole span on a granular boundary and commit only the middle; the
   reserved-but-uncommitted ends are the guard. */
#define ARC_GUARD 0x10000u

static void* reserve(uintptr_t at, size_t size) {
#ifdef _WIN32
  char* base = (char*)VirtualAlloc((LPVOID)(at - ARC_GUARD),
                                   size + 2 * ARC_GUARD, MEM_RESERVE,
                                   PAGE_NOACCESS);
  if (!base) return NULL;
  void* p = VirtualAlloc((LPVOID)at, size, MEM_COMMIT, PAGE_READWRITE);
  return (p == (void*)at) ? p : NULL;
#else
  char* base = (char*)mmap((void*)(at - ARC_GUARD), size + 2 * ARC_GUARD,
                           PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                           -1, 0);
  if (base == MAP_FAILED) return NULL;
  if (mprotect((void*)at, size, PROT_READ | PROT_WRITE) != 0) return NULL;
  return (void*)at;
#endif
}

int main(int argc, char** argv) {
  if (argc > 1 && strcmp(argv[1], "--size") == 0) {
    printf("%u\n", (unsigned)sizeof(Arm32Ctx));
    return 0;
  }
  if (argc < 3) { fprintf(stderr, "usage: cases <in> <out>\n"); return 2; }
  FILE* in = fopen(argv[1], "rb");
  FILE* out = fopen(argv[2], "wb");
  if (!in || !out) { fprintf(stderr, "cannot open state files\n"); return 2; }

  void* image = reserve(@IMAGE_BASE@, @IMAGE_SIZE@);
  void* scratch = reserve(@SCRATCH_BASE@, @SCRATCH_SIZE@);
  if (image != (void*)(uintptr_t)@IMAGE_BASE@ ||
      scratch != (void*)(uintptr_t)@SCRATCH_BASE@) {
    fprintf(stderr, "could not map at the requested base\n");
    return 2;
  }
  if (fread(image, 1, @IMAGE_SIZE@, in) == 0) return 2;

  Arm32Ctx c;
  unsigned char* pristine = (unsigned char*)malloc(@SCRATCH_SIZE@);
  for (unsigned i = 0; i < @COUNT@; ++i) {
    if (fread(&c, sizeof c, 1, in) != 1) break;
    if (fread(pristine, 1, @SCRATCH_SIZE@, in) != @SCRATCH_SIZE@) break;
    /* Restore from a pristine copy before every case. Without it each result
       depends on what ran before, and changing the emitter silently
       reshuffles which cases pass. */
    memcpy(scratch, pristine, @SCRATCH_SIZE@);
    kCases[i](&c);
    fwrite(&c, sizeof c, 1, out);
    fwrite(scratch, 1, @SCRATCH_SIZE@, out);
    fflush(out);
  }
  fclose(out);
  return 0;
}
"""


def pack_ctx(regs, flags, vec, fpscr, size: int) -> bytes:
    b = bytearray(size)
    struct.pack_into("<16I", b, 0, *regs)
    struct.pack_into("<5I", b, 64, *flags, 0)
    # The vector file is 8-aligned, which puts it after the flags with padding.
    voff = 88
    struct.pack_into("<32Q", b, voff, *vec)
    struct.pack_into("<3I", b, voff + 256, fpscr, IMAGE_BASE, 0)
    return bytes(b)


def unpack_ctx(b: bytes):
    regs = struct.unpack_from("<16I", b, 0)
    flags = struct.unpack_from("<5I", b, 64)
    vec = struct.unpack_from("<32Q", b, 88)
    fpscr, _, _ = struct.unpack_from("<3I", b, 88 + 256)
    return regs, flags, vec, fpscr


def seed(rng: random.Random, pointerish: bool):
    """One starting state.

    Pointers seeded into scratch are forward-only. Self-referential scratch
    lets an instruction walk a chain instead of faulting, which is useful --
    but pointers that can go backwards make cycles, and that only matters once
    whole functions are running. Forward-only costs nothing and keeps the two
    harnesses consistent.
    """
    regs = []
    for i in range(15):
        if pointerish:
            regs.append(SCRATCH_MID + rng.randrange(-0x400, 0x400, 4))
        else:
            regs.append(rng.getrandbits(32))
    regs.append(0)  # r15, which lifted code never reads
    regs[13] = SCRATCH_MID  # sp, so push/pop have room in both directions
    flags = tuple(rng.getrandbits(1) for _ in range(4))
    vec = []
    for _ in range(32):
        lo = struct.unpack("<I", struct.pack("<f", rng.uniform(-1e4, 1e4)))[0]
        hi = struct.unpack("<I", struct.pack("<f", rng.uniform(-1e4, 1e4)))[0]
        vec.append(lo | (hi << 32))
    scratch = bytearray(SCRATCH_SIZE)
    for off in range(0, SCRATCH_SIZE, 4):
        here = SCRATCH_BASE + off
        if rng.random() < 0.25 and here < SCRATCH_BASE + SCRATCH_SIZE - 0x100:
            value = rng.randrange(here + 4, SCRATCH_BASE + SCRATCH_SIZE, 4)
        else:
            value = rng.getrandbits(32)
        struct.pack_into("<I", scratch, off, value)
    # Only the comparison flags are seeded, not the whole of FPSCR.
    # ponytail: the emitter assumes the default rounding mode, which is what
    # the ABI sets and what C's own conversions use. Seeding RMode randomly
    # tests an assumption the generated code does not make and cannot meet --
    # it shows up as a one-ULP difference on int-to-float. If a title is ever
    # found writing FPSCR.RMode, that is when to model it.
    return regs, flags, vec, rng.getrandbits(4) << 28, bytes(scratch)


def run_oracle(case: Case, regs, flags, vec, fpscr, scratch, image, image_size):
    """Unicorn's answer, or None if it faulted -- which gates the whole case.

    The lifted side runs in this process, so it must never be handed a state
    the oracle could not survive. If Unicorn faults, the state is not a fair
    test and the case is dropped rather than being allowed to take the run
    down with it.
    """
    mode = UC_MODE_THUMB if case.thumb else UC_MODE_ARM
    mu = Uc(UC_ARCH_ARM, mode)
    # VFP is off out of reset. Grant coprocessor access, then enable the unit,
    # or every float instruction is an undefined-instruction fault.
    try:
        cpacr = mu.reg_read(uc.UC_ARM_REG_C1_C0_2)
        mu.reg_write(uc.UC_ARM_REG_C1_C0_2, cpacr | (0xF << 20))
        mu.reg_write(uc.UC_ARM_REG_FPEXC, 0x40000000)
    except UcError:
        pass
    mu.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
    mu.mem_write(IMAGE_BASE, image)
    mu.mem_map(SCRATCH_BASE, SCRATCH_SIZE, UC_PROT_ALL)
    mu.mem_write(SCRATCH_BASE, scratch)
    for i, r in enumerate(UC_R):
        mu.reg_write(r, regs[i])
    nf, zf, cf, vf = flags
    cpsr = mu.reg_read(uc.UC_ARM_REG_CPSR) & ~0xF0000000
    cpsr |= (nf << 31) | (zf << 30) | (cf << 29) | (vf << 28)
    mu.reg_write(uc.UC_ARM_REG_CPSR, cpsr)
    for i, s in enumerate(UC_S):
        mu.reg_write(s, struct.unpack("<I", struct.pack(
            "<I", (vec[i // 2] >> (32 * (i % 2))) & 0xFFFFFFFF))[0])
    mu.reg_write(uc.UC_ARM_REG_FPSCR, fpscr)
    pc = IMAGE_BASE + (case.addr - LINK_BASE)
    try:
        mu.emu_start(pc | (1 if case.thumb else 0), pc + case.size, count=1)
    except UcError:
        return None
    out_regs = [mu.reg_read(r) for r in UC_R] + [0]
    cpsr = mu.reg_read(uc.UC_ARM_REG_CPSR)
    out_flags = ((cpsr >> 31) & 1, (cpsr >> 30) & 1, (cpsr >> 29) & 1,
                 (cpsr >> 28) & 1)
    singles = [mu.reg_read(s) & 0xFFFFFFFF for s in UC_S]
    out_vec = [singles[2 * i] | (singles[2 * i + 1] << 32) for i in range(16)]
    out_vec += list(vec[16:])
    return out_regs, out_flags, out_vec, mu.mem_read(SCRATCH_BASE, SCRATCH_SIZE)


LINK_BASE = 0


def main() -> None:
    global LINK_BASE
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary")
    ap.add_argument("--slice", default="")
    ap.add_argument("--per-form", type=int, default=6,
                    help="distinct encodings to take per operand shape")
    ap.add_argument("--seeds", type=int, default=6, help="states per encoding")
    ap.add_argument("--form", default="", help="only forms containing this")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true", help="keep the work dir")
    args = ap.parse_args()

    exe_name, link_base, text_addr, code, fns = L.load(args.binary, args.slice)
    LINK_BASE = link_base
    lf = L.Lifter()
    lf.link_base = link_base

    cases = harvest(lf, code, text_addr, fns, args.per_form, args.form)
    if not cases:
        sys.exit("no testable instructions matched")
    forms = len({c.form for c in cases})
    print(f"{exe_name}: {len(cases):,} encodings over {forms} forms, "
          f"{args.seeds} states each")

    # The image both sides see. Only __text is needed -- a literal pool load
    # reaches into it and nothing here reaches further.
    image = code
    image_size = align_up(len(code) + (text_addr - link_base))
    image_full = bytearray(image_size)
    image_full[text_addr - link_base:text_addr - link_base + len(code)] = code
    image_full = bytes(image_full)

    workdir = tempfile.mkdtemp(prefix="arcverify-")
    trials = [(c, s) for c in cases for s in range(args.seeds)]
    exe = build_driver([c for c, _ in trials], image_full, workdir)

    size_out = subprocess.run([exe, "--size"], capture_output=True, text=True)
    ctx_size = int(size_out.stdout.strip())

    rng = random.Random(args.seed)
    states, expected, live = [], [], []
    for case, s in trials:
        st = seed(rng, pointerish=(s % 3 != 0))
        oracle = run_oracle(case, *st[:4], st[4], image_full, image_size)
        if oracle is None:
            continue
        live.append(case)
        states.append(st)
        expected.append(oracle)

    if not live:
        sys.exit("every state faulted in the oracle; nothing to compare")

    # Rebuild with only the cases the oracle survived, so index i on both
    # sides is the same instruction.
    exe = build_driver(live, image_full, workdir)
    in_path = os.path.join(workdir, "in.bin")
    out_path = os.path.join(workdir, "out.bin")
    with open(in_path, "wb") as fh:
        fh.write(image_full)
        for (regs, flags, vec, fpscr, scratch) in states:
            fh.write(pack_ctx(regs, flags, vec, fpscr, ctx_size))
            fh.write(scratch)
    subprocess.run([exe, in_path, out_path], capture_output=True)

    with open(out_path, "rb") as fh:
        blob = fh.read()
    stride = ctx_size + SCRATCH_SIZE
    ran = len(blob) // stride
    if ran < len(live):
        print(f"\nthe lifted side stopped after {ran} of {len(live)} cases -- "
              f"it faulted on: {live[ran].text}  ({live[ran].form})")

    bad: collections.Counter = collections.Counter()
    examples: dict = {}
    for i in range(ran):
        got = blob[i * stride:(i + 1) * stride]
        regs, flags, vec, _ = unpack_ctx(got[:ctx_size])
        mem = got[ctx_size:]
        exp_regs, exp_flags, exp_vec, exp_mem = expected[i]
        why = None
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
            off = next(k for k in range(SCRATCH_SIZE) if mem[k] != exp_mem[k])
            why = f"memory at scratch+{off:#x}"
        if why:
            bad[live[i].form] += 1
            examples.setdefault(live[i].form, (live[i].text, why))

    ok = ran - sum(bad.values())
    print(f"\nagreed: {ok:,} / {ran:,}  ({100.0 * ok / ran:.2f}%)")
    if bad:
        print("\ndisagreements, worst first:")
        for form_key, n in bad.most_common(30):
            text, why = examples[form_key]
            print(f"  {form_key:<26} {n:>4}  {text}")
            print(f"  {'':<26}       {why}")
        sys.exit(1)
    if args.keep:
        print(f"work dir: {workdir}")


if __name__ == "__main__":
    main()
