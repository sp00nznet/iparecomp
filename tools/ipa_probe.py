#!/usr/bin/env python3
"""Feasibility triage for statically recompiling an old iOS game's binary.

Reads an .ipa (or an extracted .app dir), picks a Mach-O slice, and reports the
things that decide whether a static recompile is weeks, years, or impossible:

  * whether __TEXT is still FairPlay-encrypted -- if it is, nothing else matters
  * what it links against (the framework shim surface you must write)
  * how many functions LC_FUNCTION_STARTS recovers, and how much of __text
  * the ARM/Thumb split, which a 32-bit lifter must track per function
  * how much of the binary's control flow is objc_msgSend, which is not lifted
    at all but answered by a runtime

Nothing about this is game-specific -- point it at any armv6/armv7 Mach-O.

    python tools/ipa_probe.py Game.ipa
    python tools/ipa_probe.py Payload/Game.app --slice armv7 --out docs/triage.md
"""
from __future__ import annotations

import argparse
import collections
import os
import plistlib
import struct
import sys
import zipfile

try:
    from capstone import (Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB,
                          CS_MODE_LITTLE_ENDIAN)
except ImportError:
    sys.exit("need capstone: pip install capstone")

FAT_MAGIC = 0xCAFEBABE
MH_MAGIC = 0xFEEDFACE          # 32-bit little-endian
MH_MAGIC_64 = 0xFEEDFACF

CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C
ARM_SUBTYPE = {0: "arm", 5: "armv4t", 6: "armv6", 7: "armv5tej", 8: "armv6",
               9: "armv7", 10: "armv7f", 11: "armv7s", 12: "armv7k"}

LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_UNIXTHREAD = 0x05
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x80000028

N_ARM_THUMB_DEF = 0x0008       # nlist n_desc bit: this symbol is Thumb code
N_TYPE = 0x0E
N_SECT = 0x0E
N_STAB = 0xE0

# Mnemonic prefixes a static ARM/Thumb -> C lifter cannot emit as straight-line
# C and must handle deliberately. The 32-bit set is meaningfully nastier than
# ARM64's: every instruction is predicable, the PC is a general register, and
# ldm/stm can load the PC to return.
HARD = {
    "interworking-branch": ("bx", "blx", "bxj"),
    "pc-relative-load": ("ldr",),          # refined below: only pc-relative ones
    "block-transfer": ("ldm", "stm", "push", "pop"),
    "exclusive": ("ldrex", "strex", "ldrexb", "strexb", "ldrexh", "strexh",
                  "ldrexd", "strexd", "clrex"),
    "barrier": ("dmb", "dsb", "isb"),
    "syscall": ("svc", "swi"),
    "coprocessor": ("mcr", "mrc", "mcrr", "mrrc", "cdp", "ldc", "stc"),
    "status-register": ("mrs", "msr", "cps"),
}


def _uleb(buf, i):
    r = 0
    s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, i
        s += 7


class MachO:
    """One slice of a Mach-O. 32-bit little-endian ARM only, on purpose."""

    def __init__(self, data: bytes, off: int = 0):
        self.data = data
        self.off = off
        magic, self.cputype, self.cpusubtype, self.filetype, ncmds, _, self.flags = \
            struct.unpack_from("<IiiIIII", data, off)
        if magic == MH_MAGIC_64:
            raise ValueError("64-bit Mach-O; iparecomp targets 32-bit armv6/armv7")
        if magic != MH_MAGIC:
            raise ValueError(f"not a 32-bit Mach-O (magic {magic:#x})")

        self.segments = []      # (name, vmaddr, vmsize, fileoff, filesize, [sections])
        self.sections = {}      # "SEG,sect" -> (addr, size, fileoff)
        self.dylibs = []
        self.encryption = None  # (cryptoff, cryptsize, cryptid)
        self.symtab = None
        self.function_starts = None
        self.min_os = None
        self.has_dyld_info = False
        self.entry = None

        p = off + 28
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, p)
            self._load_command(cmd, cmdsize, p)
            p += cmdsize

    def _load_command(self, cmd, cmdsize, p):
        d = self.data
        if cmd == LC_SEGMENT:
            name = d[p + 8:p + 24].rstrip(b"\0").decode("utf-8", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", d, p + 24)
            nsects = struct.unpack_from("<I", d, p + 48)[0]
            sects = []
            q = p + 56
            for _ in range(nsects):
                sn = d[q:q + 16].rstrip(b"\0").decode("utf-8", "replace")
                sg = d[q + 16:q + 32].rstrip(b"\0").decode("utf-8", "replace")
                addr, size, foff = struct.unpack_from("<III", d, q + 32)
                self.sections[f"{sg},{sn}"] = (addr, size, foff)
                sects.append(sn)
                q += 68
            self.segments.append((name, vmaddr, vmsize, fileoff, filesize, sects))
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            noff = struct.unpack_from("<I", d, p + 8)[0]
            s = d[p + noff:p + cmdsize].split(b"\0")[0]
            self.dylibs.append(s.decode("utf-8", "replace"))
        elif cmd == LC_ENCRYPTION_INFO:
            self.encryption = struct.unpack_from("<III", d, p + 8)
        elif cmd == LC_SYMTAB:
            self.symtab = struct.unpack_from("<IIII", d, p + 8)  # symoff nsyms stroff strsize
        elif cmd == LC_FUNCTION_STARTS:
            self.function_starts = struct.unpack_from("<II", d, p + 8)  # off size
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            v = struct.unpack_from("<I", d, p + 8)[0]
            self.min_os = f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            self.has_dyld_info = True
        elif cmd == LC_MAIN:
            self.entry = struct.unpack_from("<Q", d, p + 8)[0]
        elif cmd == LC_UNIXTHREAD:
            # arm thread state: 17 uint32 regs, pc is r15 (index 15)
            self.entry = struct.unpack_from("<I", d, p + 16 + 15 * 4)[0]

    @property
    def arch(self):
        return ARM_SUBTYPE.get(self.cpusubtype, f"arm?{self.cpusubtype}")

    @property
    def encrypted(self):
        return bool(self.encryption and self.encryption[2])

    def text(self):
        """(vmaddr, bytes) of __TEXT,__text."""
        if "__TEXT,__text" not in self.sections:
            return None, b""
        addr, size, foff = self.sections["__TEXT,__text"]
        return addr, self.data[self.off + foff:self.off + foff + size]

    def symbols(self):
        """[(name, value, is_thumb, is_defined)] from LC_SYMTAB."""
        if not self.symtab:
            return []
        symoff, nsyms, stroff, strsize = self.symtab
        out = []
        strs = self.data[self.off + stroff:self.off + stroff + strsize]
        for i in range(nsyms):
            b = self.off + symoff + i * 12
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBhI", self.data, b)
            if n_type & N_STAB:
                continue
            end = strs.find(b"\0", n_strx)
            name = strs[n_strx:end].decode("utf-8", "replace")
            defined = (n_type & N_TYPE) == 0x0E  # N_SECT
            out.append((name, n_value, bool(n_desc & N_ARM_THUMB_DEF), defined))
        return out

    def starts(self):
        """Function start addresses from LC_FUNCTION_STARTS, or [] if absent.

        The deltas accumulate from the address of the Mach-O header, which is
        the first segment that actually maps file bytes -- __TEXT. Starting
        from `segments[0]` instead takes __PAGEZERO, which is at address 0 with
        no content, and puts every function one __TEXT-vmaddr too low.

        The low bit is set on a Thumb function, exactly as it is in a symbol's
        value. That is the whole of the ARM/Thumb evidence in a stripped
        binary, and it is exact rather than inferred.
        """
        if not self.function_starts:
            return []
        off, size = self.function_starts
        buf = self.data[self.off + off:self.off + off + size]
        base = next((v for n, v, _, _, fs, _ in self.segments
                     if fs and n != "__PAGEZERO"),
                    self.segments[0][1] if self.segments else 0)
        addr, i, out = base, 0, []
        while i < len(buf):
            delta, i = _uleb(buf, i)
            if delta == 0:
                break
            addr += delta
            out.append(addr)
        return out


def slices(data: bytes):
    """Every Mach-O in a file, fat or thin."""
    if len(data) >= 8 and struct.unpack_from(">I", data, 0)[0] == FAT_MAGIC:
        n = struct.unpack_from(">I", data, 4)[0]
        out = []
        for i in range(n):
            cpu, sub, off, size, _ = struct.unpack_from(">IIIII", data, 8 + i * 20)
            if cpu == CPU_TYPE_ARM:
                try:
                    out.append(MachO(data, off))
                except ValueError:
                    pass
            else:
                out.append(("skip", cpu, sub))
        return [s for s in out if isinstance(s, MachO)], n
    return [MachO(data, 0)], 1


def read_app(path: str):
    """(exe_name, exe_bytes, info_plist) from an .ipa or an extracted .app."""
    if os.path.isdir(path):
        app = path
        if not app.endswith(".app"):
            cands = [d for d in os.listdir(app) if d.endswith(".app")]
            if cands:
                app = os.path.join(app, cands[0])
        info = plistlib.load(open(os.path.join(app, "Info.plist"), "rb"))
        exe = info["CFBundleExecutable"]
        return exe, open(os.path.join(app, exe), "rb").read(), info

    z = zipfile.ZipFile(path)
    plist = next((n for n in z.namelist()
                  if n.endswith(".app/Info.plist") and n.count("/") == 2), None)
    if not plist:
        sys.exit("no Payload/*.app/Info.plist -- is this an .ipa?")
    info = plistlib.loads(z.read(plist))
    exe = info["CFBundleExecutable"]
    return exe, z.read(plist[:-len("Info.plist")] + exe), info


def functions_sourced(m: MachO):
    """([(addr, size, is_thumb)], from_starts) over __TEXT,__text.

    There is no .eh_frame equivalent to lean on here: these binaries predate
    LC_FUNCTION_STARTS, so the symbol table is the only boundary evidence, and
    a function runs until the next symbol. It is also the only thing that says
    whether a given address is ARM or Thumb -- the encoding does not, and
    guessing wrong decodes one instruction set as garbage in the other.
    """
    addr, code = m.text()
    if not code:
        return []
    end = addr + len(code)

    def spans(marks):
        """[(addr, size, is_thumb)] from sorted (addr, thumb) boundaries."""
        out = []
        for i, (a, t) in enumerate(marks):
            nxt = marks[i + 1][0] if i + 1 < len(marks) else end
            if nxt > a:
                out.append((a, nxt - a, t))
        return out

    syms = spans(sorted({(v & ~1, t) for (_, v, t, d) in m.symbols()
                         if d and addr <= (v & ~1) < end}))
    starts = spans(sorted({(a & ~1, bool(a & 1)) for a in m.starts()
                           if addr <= (a & ~1) < end}))

    # Whichever accounts for more of __text. A stripped binary has no symbols
    # at all and reports nothing without this; a binary with both is better
    # served by the starts, which are complete where symbols leave the literal
    # pools uncovered.
    if sum(n for _, n, _ in starts) > sum(n for _, n, _ in syms):
        return starts, True
    return syms, False


def functions(m: MachO):
    """[(addr, size, is_thumb)] over __TEXT,__text. See functions_sourced."""
    return functions_sourced(m)[0]


def analyse(m: MachO):
    """Instruction histogram and lifter special-cases for one slice.

    Disassembled one function at a time, each in the instruction set its own
    symbol declares. A single linear sweep does not work on a 32-bit binary:
    capstone halts at the first byte that will not decode, and in a mixed
    ARM/Thumb image that is the first function in the other mode.
    """
    addr, code = m.text()
    if not code:
        return None
    fns, from_starts = functions_sourced(m)

    md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

    hist = collections.Counter()
    hard = collections.Counter()
    pcrel = total = covered = 0
    for a, size, is_thumb in fns:
        body = code[a - addr:a - addr + size]
        md = md_t if is_thumb else md_a
        for ins in md.disasm(body, a):
            total += 1
            covered += ins.size
            base = ins.mnemonic.split(".")[0]
            hist[ins.mnemonic] += 1
            for kind, prefixes in HARD.items():
                if kind == "pc-relative-load":
                    continue
                if base.startswith(prefixes):
                    hard[kind] += 1
                    break
            # The PC is a general register on 32-bit ARM: it is read for
            # literal pools and written to return. Both need the lifter's help.
            if "pc" in ins.op_str and base.startswith(("ldr", "add", "mov", "sub")):
                pcrel += 1
    hard["pc-relative-load"] = pcrel

    thumb_fns = sum(1 for _, _, t in fns if t)
    return dict(total=total, hist=hist, hard=hard, size=len(code),
                fns=len(fns), thumb_fns=thumb_fns, arm_fns=len(fns) - thumb_fns,
                from_starts=from_starts, covered=covered,
                coverage=100.0 * covered / len(code) if code else 0.0)


def objc_stats(m: MachO):
    """Objective-C weight: classes, selectors, and how much of the binary is
    dynamic dispatch that a lifter will never resolve statically."""
    out = {}
    for key, per in (("__DATA,__objc_classlist", 4),
                     ("__DATA,__objc_selrefs", 4),
                     ("__DATA,__objc_protolist", 4),
                     ("__DATA,__objc_catlist", 4)):
        if key in m.sections:
            out[key.split(",")[1]] = m.sections[key][1] // per
    return out


def report(path, exe, info, ms, nslices, sel, an, out):
    w = out.write
    ident = info.get("CFBundleIdentifier", "?")
    ver = info.get("CFBundleVersion", "?")
    w(f"# Triage: `{exe}`\n\n")
    w(f"- bundle: `{ident}` {ver}\n")
    w(f"- slices: {nslices} ({', '.join(m.arch for m in ms)})\n")
    w(f"- analysed: **{sel.arch}**, min iPhone OS {sel.min_os or 'unstated'}\n")

    if sel.encrypted:
        coff, csize, cid = sel.encryption
        w(f"\n## STOP -- `__TEXT` is FairPlay-encrypted\n\n")
        w(f"`LC_ENCRYPTION_INFO` cryptid={cid}, {csize:,} bytes from {coff:#x}.\n")
        w("Nothing below this line is meaningful: the bytes the lifter would read\n")
        w("are ciphertext. A decrypted dump of the same binary is required.\n")
    else:
        w("- `__TEXT`: **not encrypted**"
          + (" (`LC_ENCRYPTION_INFO` present, cryptid=0)\n"
             if sel.encryption else " (no `LC_ENCRYPTION_INFO`)\n"))

    addr, code = sel.text()
    w(f"- `__text`: {len(code)/1e6:.2f} MB @ {addr:#x}\n")
    starts = sel.starts()
    syms = sel.symbols()
    defined = [s for s in syms if s[3]]
    undef = [s for s in syms if not s[3]]
    if starts:
        w(f"- functions from `LC_FUNCTION_STARTS`: **{len(starts):,}**\n")
    else:
        w("- `LC_FUNCTION_STARTS`: **absent** -- function boundaries must be\n"
          "  recovered from the symbol table and by following calls\n")
    w(f"- symbols: {len(defined):,} defined, {len(undef):,} undefined\n")

    if an:
        # Say which source the boundaries actually came from: on a stripped
        # binary the symbol table contributes nothing and the starts are
        # everything, and a reader deciding whether a title is viable needs to
        # know which of the two they are looking at.
        source = ("`LC_FUNCTION_STARTS`" if an.get("from_starts")
                  else "the symbol table")
        w(f"- functions from {source}: **{an['fns']:,}** "
          f"covering {an['coverage']:.1f}% of `__text`\n")
        w(f"- instruction sets: **{an['arm_fns']:,} ARM, {an['thumb_fns']:,} Thumb** "
          f"({100.0 * an['thumb_fns'] / an['fns']:.0f}% Thumb)\n"
          if an['fns'] else "")
        w(f"- instructions: {an['total']:,} ({len(an['hist'])} distinct mnemonics)\n")
        w(f"- undecoded bytes: {an['size'] - an['covered']:,}\n")

    w("\n## Shim surface\n\nEvery framework here is a shim you write:\n\n")
    for d in sel.dylibs:
        w(f"- `{d}`\n")

    o = objc_stats(sel)
    if o:
        w("\n## Objective-C weight\n\n")
        w("| section | count |\n|---|---|\n")
        for k, v in o.items():
            w(f"| `{k}` | {v:,} |\n")
        w("\nSelector references are the honest measure of how much control flow\n"
          "goes through `objc_msgSend`. That dispatch is never lifted -- it is\n"
          "answered by a runtime, and every one of those selectors must resolve.\n")

    if an:
        w("\n## Constructs the lifter must special-case\n\n")
        w("| construct | count |\n|---|---|\n")
        for k in HARD:
            w(f"| {k} | {an['hard'].get(k, 0):,} |\n")
        w("\n## Top mnemonics\n\n| mnemonic | count |\n|---|---|\n")
        for mn, c in an["hist"].most_common(25):
            w(f"| `{mn}` | {c:,} |\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help=".ipa file or extracted .app directory")
    ap.add_argument("--slice", help="armv6 / armv7; default is the newest present")
    ap.add_argument("--out", help="write markdown here instead of stdout")
    a = ap.parse_args()

    exe, data, info = read_app(a.path)
    ms, nslices = slices(data)
    if not ms:
        sys.exit("no 32-bit ARM slice -- iparecomp targets armv6/armv7")
    sel = None
    if a.slice:
        sel = next((m for m in ms if m.arch == a.slice), None)
        if not sel:
            sys.exit(f"no {a.slice} slice; have {[m.arch for m in ms]}")
    else:
        sel = sorted(ms, key=lambda m: m.cpusubtype)[-1]

    an = None if sel.encrypted else analyse(sel)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            report(a.path, exe, info, ms, nslices, sel, an, f)
        print(f"wrote {a.out}")
    else:
        report(a.path, exe, info, ms, nslices, sel, an, sys.stdout)


if __name__ == "__main__":
    main()
