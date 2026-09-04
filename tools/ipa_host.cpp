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
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "macho_image.h"

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
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--help" || a == "-h") { Usage(); return 0; }
    else if (a == "--arch" && i + 1 < argc) arch = argv[++i];
    else if (a.rfind("--arch=", 0) == 0) arch = a.substr(7);
    else if (a.rfind("--contract=", 0) == 0) contract = a.substr(11);
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

  uint32_t lo = 0xFFFFFFFFu, hi = 0;
  for (const auto& s : img.segments()) {
    if (!s.vmsize) continue;
    lo = std::min(lo, s.vmaddr);
    hi = std::max(hi, s.vmaddr + s.vmsize);
  }
  std::printf("\nbase       %08X, span %.1f MB\n", lo, (hi - lo) / 1e6);
  std::printf("slide      %08X\n", img.slide());
  std::printf("segments   %zu\n", img.segments().size());
  for (const auto& s : img.segments())
    std::printf("           %-12s %08X +%#x\n", s.name.c_str(), s.vmaddr, s.filesize);

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
