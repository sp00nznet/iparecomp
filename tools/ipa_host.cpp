// ipa_host -- load an old iOS app's binary and report what it still needs.
//
// Point it at the Mach-O inside an extracted .app. It picks a 32-bit ARM
// slice, parses its load commands, maps its segments and prints what nothing
// yet provides, grouped by the framework that owes it. That list is the port's
// work queue, and it shrinks as the shim grows.
//
// Unlike the ELF side, the grouping is not guessed from name prefixes: every
// undefined symbol in a Mach-O names the dylib it expects, so the work list is
// exact.
//
// Nothing here can execute the image. These binaries are 32-bit ARM and no
// modern host runs that natively, so iparecomp is a lifting project from the
// first day -- there is no arm64-host shortcut of the kind androidrecomp gets.
#include <algorithm>
#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "macho_image.h"
#include "arc_boot.h"
#include "objc_runtime.h"

namespace {

void Usage() {
  std::puts(
      "usage: ipa_host [--arch armv6|armv7] [--contract=file] <path/to/binary>\n"
      "\n"
      "  --arch      which slice to load; default is the newest ARM slice\n"
      "  --contract  a file of entry points the host must drive, one per line;\n"
      "              with none, every Objective-C class in the binary is listed,\n"
      "              which is how you discover a title's contract.");
}

// The generated program installs its own dispatch table, and this tool is
// built both with and without one. Rather than two builds, the symbol is
// weak: present when the lifted program is linked in, null when it is not, and
// the runtime then resolves branches against the shims alone.
#if defined(__GNUC__)
extern "C" void arc_install_lifted(uint32_t) __attribute__((weak));
static void (*ArcInstallLifted())(uint32_t) { return arc_install_lifted; }
#else
static void (*ArcInstallLifted())(uint32_t) { return nullptr; }
#endif

// Where a lifted branch would have gone. Recording it instead of taking it is
// what lets the dispatch check run in a build with no lifted program.
uint32_t g_last_dispatch = 0;
void RecordDispatch(Arm32Ctx*, uint32_t target) { g_last_dispatch = target; }

std::vector<std::string> ReadContract(const std::string& path) {
  std::vector<std::string> out;
  std::ifstream f(path);
  std::string line;
  while (std::getline(f, line)) {
    size_t a = line.find_first_not_of(" \t\r");
    if (a == std::string::npos || line[a] == '#') continue;
    size_t b = line.find_last_not_of(" \t\r");
    out.push_back(line.substr(a, b - a + 1));
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  std::string path, arch, contract;
  bool want_objc = false;
  bool want_run = false;
  bool permissive = false;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--help" || a == "-h") { Usage(); return 0; }
    else if (a == "--arch" && i + 1 < argc) arch = argv[++i];
    else if (a.rfind("--arch=", 0) == 0) arch = a.substr(7);
    else if (a.rfind("--contract=", 0) == 0) contract = a.substr(11);
    else if (a == "--objc") want_objc = true;
    else if (a == "--run") want_run = true;
    else if (a == "--permissive") { want_run = true; permissive = true; }
    else path = a;
  }
  if (path.empty()) { Usage(); return 2; }

  arc::MachOImage img;
  if (!img.Load(path, arch)) {
    std::printf("cannot load: %s\n", img.error().c_str());
    // An encrypted binary is the single most common reason a target is not
    // viable, so it earns an explanation rather than a bare failure.
    if (img.error().find("FairPlay") != std::string::npos) {
      std::puts(
          "\nThis is an App Store binary with its __TEXT still encrypted. The\n"
          "bytes a lifter would read are ciphertext, so no amount of shim work\n"
          "helps. Triage another dump of the same app with tools/ipa_probe.py\n"
          "before spending time here.");
    }
    return 1;
  }

  std::printf("image      %s\n", path.c_str());
  std::printf("arch       %s\n", img.arch().c_str());

  std::puts("\ndependencies");
  for (const auto& d : img.dylibs()) std::printf("  %s\n", d.c_str());

  if (!img.Map()) {
    std::printf("\nmap failed: %s\n", img.error().c_str());
    return 1;
  }

  uint32_t hi = 0;
  for (const auto& s : img.segments()) {
    if (!s.vmsize || s.name == "__PAGEZERO") continue;
    hi = std::max(hi, s.vmaddr + s.vmsize);
  }
  std::printf("\nlink base  %08X, span %.1f MB\n", img.link_base(),
              (hi - img.link_base()) / 1e6);
  // The slide is always zero, and saying so is the point: these binaries carry
  // no relocations, so an image anywhere but its link address would have every
  // absolute pointer in it wrong.
  std::printf("slide      %08X%s\n", img.slide(),
              img.slide() ? "  -- WRONG, the image cannot be slid" : "");
  std::printf("segments   %zu\n", img.segments().size());
  for (const auto& s : img.segments()) {
    // Where each segment actually landed, so "mapped at its link address" is
    // something the tool demonstrates rather than something it claims. A
    // segment below the low floor is left unmapped on purpose: no desktop OS
    // hands out the first 64 KB, and once the lifter folds literal-pool loads
    // nothing reads it.
    const char* note = "";
    if (!s.mapped)
      note = s.name == "__PAGEZERO" ? "  (not mapped, by design)"
                                    : "  (below the 64 KB floor, unmapped)";
    else if (uintptr_t(s.mapped) != uintptr_t(s.vmaddr) &&
             uintptr_t(s.mapped) != uintptr_t(0x10000))
      note = "  -- NOT at its link address";
    std::printf("           %-12s %08X +%#-8x host %p%s\n", s.name.c_str(),
                s.vmaddr, s.filesize, s.mapped, note);
  }

  // The Objective-C half. Reported rather than reverse engineered: the ABI
  // writes the class table into __DATA in a documented layout, and the bind
  // table says exactly where the class graph leaves the binary.
  if (want_objc) {
    if (!arc::Objc().Init(img)) {
      std::printf("\nobjc: %s\n", arc::Objc().error().c_str());
      return 1;
    }
    size_t methods = 0, external = 0;
    for (const auto& c : arc::Objc().classes()) {
      methods += c.methods.size();
      if (!c.external_super.empty()) ++external;
    }
    std::printf("\nobjc classes  %zu (%zu of them inherit from a framework "
                "class)\n", arc::Objc().classes().size(), external);
    std::printf("objc methods  %zu defined, %zu (class, selector) pairs "
                "resolved\n", methods, arc::Objc().method_count());

    // Send some real messages down the exact path a lifted `bl` takes: the
    // import stub, the runtime's native table, objc_msgSend, the method
    // lookup, and out to the implementation's address. Nothing is stubbed
    // here except the final branch, which is recorded rather than taken so
    // that this works without the lifted program linked in.
    arc::InstallObjcRuntime(img);
    const arc::Section* bss = img.FindSection("__DATA", "__bss");
    uint32_t stub = 0;
    for (const auto& im : img.imports())
      if (im.name == "_objc_msgSend") stub = im.stub;
    if (bss && bss->size >= 4 && stub) {
      arc_set_dispatch(RecordDispatch);
      size_t sent = 0, agreed = 0;
      for (const auto& c : arc::Objc().classes()) {
        if (c.methods.empty()) continue;
        const arc::ObjcMethod& m = c.methods.front();
        // A receiver is just a word holding its class. __bss is zeroed and
        // nothing has run, so borrowing four bytes of it is safe; it is put
        // back immediately.
        const uint32_t obj = bss->addr;
        const uint32_t saved = ARC_LD32(obj);
        ARC_ST32(obj, c.addr);
        Arm32Ctx ctx;
        std::memset(&ctx, 0, sizeof ctx);
        ctx.image_base = img.link_base();
        ARC_W(&ctx, 0, obj);
        ARC_W(&ctx, 1, m.selector_addr);
        g_last_dispatch = 0;
        // A message that finds nothing traps, and a trap here is a result
        // rather than a reason to stop: catch it, count it, keep going.
        std::jmp_buf recovery;
        arc_set_recovery(&recovery);
        const bool trapped = setjmp(recovery) != 0;
        if (!trapped) arc_dispatch_miss(&ctx, stub);
        arc_set_recovery(nullptr);
        ARC_ST32(obj, saved);
        ++sent;
        if (!trapped && g_last_dispatch == m.imp) {
          ++agreed;
        } else if (sent - agreed <= 3) {
          std::printf("  MISS %s%s %s -- %s\n", c.meta ? "+" : "-",
                      c.name.c_str(), m.selector.c_str(),
                      trapped ? arc_last_trap() : "wrong implementation");
        }
      }
      arc_set_dispatch(nullptr);
      std::printf("dispatch      %zu/%zu messages reached the right "
                  "implementation\n", agreed, sent);
    }

    const auto& owed = arc::Objc().unanswered();
    std::printf("\nselectors     %zu referenced: %zu answered by this "
                "binary's own classes,\n              %zu owed by the "
                "frameworks\n",
                arc::Objc().referenced(), arc::Objc().answered(), owed.size());
    // The shim work list. Exact in the same sense the import list is: it says
    // what is sent and not implemented, without guessing at receivers.
    for (size_t i = 0; i < owed.size(); ++i)
      std::printf("    %s\n", owed[i].c_str());

    // The table itself. Empty classes are printed too: a class with no
    // methods of its own is not nothing -- it inherits -- and leaving it
    // out makes the listing look like it lost one.
    for (const auto& c : arc::Objc().classes()) {
      std::printf("\n%s%s : %s\n", c.meta ? "+" : "", c.name.c_str(),
                  c.external_super.empty() ? "(in image)"
                                           : c.external_super.c_str());
      for (const auto& m : c.methods)
        std::printf("    %-48s %#010x%s\n", m.selector.c_str(), m.imp,
                    m.from_category ? "  (category)" : "");
    }
    return 0;
  }

  // Start the guest. Nothing about this expects to reach a window yet: the
  // point is that where it stops is a fact rather than a guess, and the trail
  // it leaves names the next thing to write.
  if (want_run) {
    const arc::BootResult r = arc::Boot(img, ArcInstallLifted(), permissive);
    std::printf("\nshims      %zu imports claimed, %zu still owed\n", r.shims,
                r.outstanding);
    std::printf("classrefs  %zu framework class references bound\n",
                r.bound_classes);
    std::printf("entry      %#010x\n", r.entry);
    if (!r.started) {
      std::printf("did not start: %s\n", r.trap.c_str());
      return 1;
    }
    if (r.trapped) {
      std::printf("\nstopped: %s\n", r.trap.c_str());
      arc::ReportTrail(img);
      return 1;
    }
    std::printf("\nthe guest returned from its entry point without trapping\n");
    arc::ReportTrail(img);
    return 0;
  }

  const size_t thumb = img.thumb_count();
  const size_t total = img.exports().size();
  std::printf("\nsymbols    %zu defined, %zu undefined\n", total, img.imports().size());
  std::printf("           %zu ARM, %zu Thumb (%.0f%% Thumb)\n",
              total - thumb, thumb, total ? 100.0 * double(thumb) / double(total) : 0.0);
  if (thumb == 0 && total)
    std::puts("           single instruction set -- no interworking to lift");

  // Nothing is bound yet: the shim does not exist. Grouping by the owing
  // framework is what turns 300 undefined symbols into a handful of decisions.
  std::map<std::string, std::vector<std::string>> owed;
  for (const auto& im : img.imports())
    if (!im.bound) owed[im.dylib].push_back(im.name);

  size_t outstanding = 0;
  for (auto& [lib, syms] : owed) outstanding += syms.size();
  std::printf("\nimports    %zu total, %zu outstanding\n",
              img.imports().size(), outstanding);
  for (auto& [lib, syms] : owed) {
    std::sort(syms.begin(), syms.end());
    std::printf("\n  %s -- %zu\n", lib.c_str(), syms.size());
    size_t shown = 0;
    for (const auto& s : syms) {
      if (shown++ == 12) { std::printf("    ... and %zu more\n", syms.size() - 12); break; }
      std::printf("    %s\n", s.c_str());
    }
  }

  if (!contract.empty()) {
    std::printf("\nhost contract (%s)\n", contract.c_str());
    for (const auto& want : ReadContract(contract)) {
      bool found = false;
      for (const auto& e : img.exports())
        if (e.name == want || e.name == "_" + want) { found = true; break; }
      std::printf("  %-44s %s\n", want.c_str(), found ? "found" : "MISSING");
    }
  }

  std::puts(
      "\n32-bit ARM: image loaded and inspected, but no host runs these\n"
      "            instructions natively. Running it needs the lifter.");
  return 0;
}
