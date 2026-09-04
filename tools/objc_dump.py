#!/usr/bin/env python3
"""Read the Objective-C class metadata out of a 32-bit ARM Mach-O.

An iOS app's host contract is not a list of C entry points the way a JNI
bridge is -- it is a set of classes the host must instantiate and selectors it
must send. That information is not reverse-engineered: the ObjC 2.0 ABI writes
the whole class table into __DATA in a documented layout, so it can simply be
read.

This is also the evidence that the msgSend-as-shim design is tractable. If the
class table were opaque, the runtime would have nothing to build from.

    python tools/objc_dump.py Payload/Game.app/Game
    python tools/objc_dump.py Payload/Game.app/Game --contract > contract/app.txt
"""
from __future__ import annotations

import argparse
import struct
import sys

sys.path.insert(0, __file__.rsplit("ipa", 1)[0] if False else "")
from ipa_probe import MachO, read_app, slices  # noqa: E402

# class_t, 32-bit: isa, superclass, cache, vtable, ro
CLASS_RO_OFF = 16
# class_ro_t, 32-bit: flags, instanceStart, instanceSize, ivarLayout, name,
#                     baseMethodList, ...
RO_NAME_OFF = 16
RO_METHODS_OFF = 20
# method_t, 32-bit: name(SEL), types, imp
METHOD_SIZE = 12


class Reader:
    """Virtual address -> bytes, using the section table as the map."""

    def __init__(self, m: MachO):
        self.m = m
        self.spans = []
        for (addr, size, foff) in m.sections.values():
            if size:
                self.spans.append((addr, size, foff))

    def at(self, vaddr, n):
        for addr, size, foff in self.spans:
            if addr <= vaddr < addr + size:
                off = self.m.off + foff + (vaddr - addr)
                return self.m.data[off:off + n]
        return b""

    def u32(self, vaddr):
        b = self.at(vaddr, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else 0

    def cstr(self, vaddr, limit=256):
        b = self.at(vaddr, limit)
        end = b.find(b"\0")
        return b[:end if end >= 0 else limit].decode("utf-8", "replace")


def classes(m: MachO):
    """[(class_name, [(selector, imp_addr)])] from __objc_classlist."""
    key = "__DATA,__objc_classlist"
    if key not in m.sections:
        return []
    addr, size, _ = m.sections[key]
    r = Reader(m)
    out = []
    for i in range(size // 4):
        cls = r.u32(addr + i * 4)
        if not cls:
            continue
        ro = r.u32(cls + CLASS_RO_OFF)
        if not ro:
            continue
        name = r.cstr(r.u32(ro + RO_NAME_OFF))
        methods = []
        ml = r.u32(ro + RO_METHODS_OFF)
        if ml:
            entsize = r.u32(ml)
            count = r.u32(ml + 4)
            # entsize is the stride; trust it over the struct size, since
            # some toolchains pad. Refuse anything implausible rather than
            # walking off into the heap.
            if entsize < METHOD_SIZE or entsize > 64 or count > 4096:
                entsize, count = METHOD_SIZE, min(count, 4096)
            for k in range(count):
                e = ml + 8 + k * entsize
                sel = r.cstr(r.u32(e))
                imp = r.u32(e + 8)
                if sel:
                    methods.append((sel, imp))
        out.append((name, methods))
    return out


def selrefs(m: MachO):
    key = "__DATA,__objc_selrefs"
    if key not in m.sections:
        return []
    addr, size, _ = m.sections[key]
    r = Reader(m)
    out = []
    for i in range(size // 4):
        s = r.cstr(r.u32(addr + i * 4))
        if s:
            out.append(s)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--arch")
    ap.add_argument("--contract", action="store_true",
                    help="emit a contract file rather than a listing")
    ap.add_argument("--selectors", action="store_true",
                    help="list every referenced selector")
    a = ap.parse_args()

    _, data, _ = read_app(a.path)
    ms, _ = slices(data)
    m = next((x for x in ms if x.arch == a.arch), None) if a.arch else \
        sorted(ms, key=lambda x: x.cpusubtype)[-1]
    if m.encrypted:
        sys.exit("__TEXT is FairPlay-encrypted; nothing to read")

    cs = classes(m)
    if a.selectors:
        for s in sorted(set(selrefs(m))):
            print(s)
        return
    if a.contract:
        print("# Objective-C classes defined by this binary, and their methods.")
        print("# The host instantiates the delegate and the view; everything else")
        print("# is reached through objc_msgSend and needs no host code.")
        print(f"# {len(cs)} classes, {sum(len(x[1]) for x in cs)} methods.\n")
        for name, methods in sorted(cs):
            print(f"{name}")
            for sel, imp in methods:
                print(f"    -{sel:<48} {imp:#010x}")
            print()
        return

    print(f"{len(cs)} classes, {sum(len(x[1]) for x in cs)} methods, "
          f"{len(set(selrefs(m)))} distinct selectors referenced\n")
    for name, methods in sorted(cs):
        print(f"  {name:<40} {len(methods):>3} methods")


if __name__ == "__main__":
    main()
