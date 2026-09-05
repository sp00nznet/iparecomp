#!/usr/bin/env python3
"""Check the C Objective-C runtime against the Python reader.

Two independent walks of the same ABI. `objc_dump.py` reads the file with
struct offsets and a section table; `runtime/objc_runtime.cpp` reads the mapped
image and additionally realizes metaclasses and merges categories. Neither is
derived from the other, so agreement means the layout was read correctly rather
than that one bug was written twice.

The C side must contain the Python side exactly, and its surplus must be
explainable -- metaclasses and category methods, nothing else. A selector that
appears in one and not the other is a real disagreement about the class table,
which is the sort of thing that would otherwise show up much later as a message
going to the wrong implementation.

    python tools/objc_verify.py path/to/Game --host build/ipa_host

`ipa_host --objc` also self-checks the dispatch path while it runs: it sends a
real message per class through the import stub, the native table and the
runtime, and confirms it arrives at the implementation the table names. That
number is reported here too.
"""
from __future__ import annotations

import argparse
import collections
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import objc_dump  # noqa: E402
from ipa_probe import read_app, slices  # noqa: E402


def python_table(path: str):
    _, data, _ = read_app(path)
    ms, _ = slices(data)
    m = ms[0]
    return {name: {(sel, imp) for sel, imp in methods}
            for name, methods in objc_dump.classes(m)}


def c_table(host: str, binary: str):
    """(classes, category methods, metaclass names, the tool's own numbers)."""
    out = subprocess.run([host, "--objc", binary], capture_output=True,
                         text=True).stdout
    classes: dict = {}
    cats: collections.defaultdict = collections.defaultdict(set)
    meta = set()
    notes = []
    cur = None
    for line in out.splitlines():
        if line.startswith(("objc ", "dispatch ", "selectors ")):
            notes.append(line.rstrip())
        elif line and not line.startswith(" ") and " : " in line:
            cur = line.split(" : ")[0]
            if cur.startswith("+"):
                meta.add(cur)
            classes.setdefault(cur, set())
        elif line.startswith("    ") and cur and cur in classes:
            parts = line.split()
            if len(parts) < 2 or not parts[1].startswith("0x"):
                continue
            entry = (parts[0], int(parts[1], 16))
            if "(category)" in line:
                cats[cur].add(entry)
            classes[cur].add(entry)
    return classes, cats, meta, notes


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("binary", help="the Mach-O, .app directory, or .ipa")
    ap.add_argument("--host", default="build/ipa_host",
                    help="the built ipa_host to compare against")
    ap.add_argument("--raw", default="",
                    help="the same binary as a bare Mach-O, if `binary` is an "
                         ".ipa that ipa_host cannot open directly")
    args = ap.parse_args()

    host_target = args.raw or args.binary
    if not os.path.exists(args.host) and os.path.exists(args.host + ".exe"):
        args.host += ".exe"
    if not os.path.exists(args.host):
        sys.exit(f"no such host tool: {args.host} -- build it first")

    py = python_table(args.binary)
    classes, cats, meta, notes = c_table(args.host, host_target)
    instance = {k: v for k, v in classes.items() if not k.startswith("+")}

    print(f"python : {len(py)} classes, {sum(len(v) for v in py.values())} methods")
    print(f"C      : {len(classes)} classes ({len(meta)} metaclasses), "
          f"{sum(len(v) for v in classes.values())} methods, "
          f"{sum(len(v) for v in cats.values())} from categories")
    for n in notes:
        print(f"         {n}")

    missing, extra = {}, {}
    for name, methods in py.items():
        got = instance.get(name, set())
        if methods - got:
            missing[name] = methods - got
        surplus = got - methods - cats.get(name, set())
        if surplus:
            extra[name] = surplus
    only_py = sorted(set(py) - set(instance))
    only_c = sorted(set(instance) - set(py))

    bad = False
    for label, table in (("missing from the C table", missing),
                         ("in the C table and not a category", extra)):
        if table:
            bad = True
            print(f"\n{label} ({len(table)} classes):")
            for k, v in list(table.items())[:10]:
                print(f"  {k}: {sorted(s for s, _ in v)[:8]}")
    if only_py:
        bad = True
        print(f"\nclasses only the Python reader found: {only_py}")
    if only_c:
        bad = True
        print(f"\nclasses only the C runtime found: {only_c}")

    if bad:
        sys.exit(1)
    print("\nagree: every class and every (selector, imp) matches, and the C "
          "table's\n       surplus is exactly metaclasses and categories.")


if __name__ == "__main__":
    main()
