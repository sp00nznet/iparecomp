#include "macho_image.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace arc {
namespace {

constexpr uint32_t kFatMagic = 0xCAFEBABE;
constexpr uint32_t kMachMagic32 = 0xFEEDFACE;
constexpr uint32_t kMachMagic64 = 0xFEEDFACF;
constexpr uint32_t kCpuTypeArm = 12;

constexpr uint32_t LC_SEGMENT = 0x01;
constexpr uint32_t LC_SYMTAB = 0x02;
constexpr uint32_t LC_UNIXTHREAD = 0x05;
constexpr uint32_t LC_DYSYMTAB = 0x0B;
constexpr uint32_t LC_LOAD_DYLIB = 0x0C;
constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x80000018;
constexpr uint32_t LC_ENCRYPTION_INFO = 0x21;
constexpr uint32_t LC_MAIN = 0x80000028;

constexpr uint8_t N_STAB = 0xE0;
constexpr uint8_t N_TYPE = 0x0E;
constexpr uint8_t N_UNDF = 0x00;
constexpr uint8_t N_SECT = 0x0E;
constexpr uint16_t N_ARM_THUMB_DEF = 0x0008;

// The dylib a given undefined symbol is expected to come from lives in the top
// byte of n_desc. Ordinal 0 means "self", and the special values above 0xFD
// mean dynamic lookup or the executable itself.
inline uint8_t LibraryOrdinal(uint16_t desc) { return (desc >> 8) & 0xFF; }

uint32_t Be32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

std::string SubtypeName(int32_t sub) {
  switch (sub) {
    case 0: return "arm";
    case 5: return "armv4t";
    case 6: case 8: return "armv6";
    case 9: return "armv7";
    case 11: return "armv7s";
    case 12: return "armv7k";
    default: return "arm?";
  }
}

// The leaf of a dylib install path is what anyone actually calls the framework.
std::string ShortDylib(const std::string& path) {
  size_t slash = path.find_last_of('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

}  // namespace

bool MachOImage::Load(const std::string& path, const std::string& want_arch) {
  std::ifstream f(path, std::ios::binary);
  if (!f) { error_ = "cannot open " + path; return false; }
  file_.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  if (file_.size() < 32) { error_ = "too small to be a Mach-O"; return false; }

  // A fat file lists its slices big-endian ahead of the images themselves.
  std::vector<size_t> candidates;
  if (Be32(file_.data()) == kFatMagic) {
    uint32_t n = Be32(file_.data() + 4);
    for (uint32_t i = 0; i < n; ++i) {
      const uint8_t* a = file_.data() + 8 + i * 20;
      if (a + 20 > file_.data() + file_.size()) break;
      if (Be32(a) != kCpuTypeArm) continue;   // 64-bit slices are not ours
      candidates.push_back(Be32(a + 8));
    }
    if (candidates.empty()) { error_ = "no 32-bit ARM slice in fat binary"; return false; }
  } else {
    candidates.push_back(0);
  }

  // Prefer an explicitly requested arch, else the newest ARM slice present.
  size_t chosen = candidates.front();
  int32_t best = -1;
  for (size_t off : candidates) {
    if (off + 28 > file_.size()) continue;
    uint32_t magic;
    int32_t cputype, cpusubtype;
    memcpy(&magic, file_.data() + off, 4);
    memcpy(&cputype, file_.data() + off + 4, 4);
    memcpy(&cpusubtype, file_.data() + off + 8, 4);
    if (magic == kMachMagic64) continue;
    if (magic != kMachMagic32 || cputype != int32_t(kCpuTypeArm)) continue;
    std::string name = SubtypeName(cpusubtype);
    if (!want_arch.empty()) {
      if (name == want_arch) { chosen = off; best = cpusubtype; arch_ = name; break; }
      continue;
    }
    if (cpusubtype > best) { best = cpusubtype; chosen = off; arch_ = name; }
  }
  if (best < 0) {
    error_ = want_arch.empty() ? "no usable 32-bit ARM slice"
                               : "no " + want_arch + " slice";
    return false;
  }
  slice_ = chosen;

  const uint8_t* base = file_.data() + slice_;
  uint32_t ncmds;
  memcpy(&ncmds, base + 16, 4);

  std::vector<std::string> ordinal_dylibs;   // index 1 = first LC_LOAD_DYLIB
  const uint8_t* p = base + 28;
  const uint8_t* end = file_.data() + file_.size();
  uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;

  for (uint32_t i = 0; i < ncmds && p + 8 <= end; ++i) {
    uint32_t cmd, cmdsize;
    memcpy(&cmd, p, 4);
    memcpy(&cmdsize, p + 4, 4);
    if (cmdsize < 8 || p + cmdsize > end) break;

    if (cmd == LC_SEGMENT) {
      Segment s;
      char nm[17] = {0};
      memcpy(nm, p + 8, 16);
      s.name = nm;
      memcpy(&s.vmaddr, p + 24, 4);
      memcpy(&s.vmsize, p + 28, 4);
      memcpy(&s.fileoff, p + 32, 4);
      memcpy(&s.filesize, p + 36, 4);
      memcpy(&s.maxprot, p + 40, 4);
      memcpy(&s.initprot, p + 44, 4);
      uint32_t nsects;
      memcpy(&nsects, p + 48, 4);
      const uint8_t* q = p + 56;
      for (uint32_t k = 0; k < nsects && q + 68 <= p + cmdsize; ++k, q += 68) {
        Section sec;
        char sn[17] = {0}, sg[17] = {0};
        memcpy(sn, q, 16);
        memcpy(sg, q + 16, 16);
        sec.name = sn;
        sec.segment = sg;
        memcpy(&sec.addr, q + 32, 4);
        memcpy(&sec.size, q + 36, 4);
        memcpy(&sec.fileoff, q + 40, 4);
        sections_.push_back(sec);
      }
      segments_.push_back(s);
    } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB) {
      uint32_t noff;
      memcpy(&noff, p + 8, 4);
      if (noff < cmdsize) {
        const char* s = reinterpret_cast<const char*>(p + noff);
        size_t maxlen = cmdsize - noff;
        std::string full(s, strnlen(s, maxlen));
        dylibs_.push_back(full);
        ordinal_dylibs.push_back(ShortDylib(full));
      }
    } else if (cmd == LC_ENCRYPTION_INFO) {
      uint32_t cryptid;
      memcpy(&cryptid, p + 16, 4);
      encrypted_ = cryptid != 0;
    } else if (cmd == LC_SYMTAB) {
      memcpy(&symoff, p + 8, 4);
      memcpy(&nsyms, p + 12, 4);
      memcpy(&stroff, p + 16, 4);
      memcpy(&strsize, p + 20, 4);
    } else if (cmd == LC_MAIN) {
      uint64_t off64;
      memcpy(&off64, p + 8, 8);
      entry_ = uint32_t(off64);
    } else if (cmd == LC_UNIXTHREAD) {
      // arm_thread_state: flavour, count, then r0..r15; pc is r15.
      memcpy(&entry_, p + 16 + 15 * 4, 4);
    }
    p += cmdsize;
  }

  if (encrypted_) {
    error_ = "__TEXT is FairPlay-encrypted (cryptid=1); a decrypted dump is required";
    return false;
  }

  // Symbols. Undefined ones are the shim surface and carry the ordinal of the
  // dylib that owes them; defined ones are what a lifter will emit, and their
  // Thumb bit is the only record of which instruction set each one is in.
  if (nsyms && stroff + strsize <= file_.size() - slice_) {
    const uint8_t* syms = base + symoff;
    const char* strs = reinterpret_cast<const char*>(base + stroff);
    for (uint32_t i = 0; i < nsyms; ++i) {
      const uint8_t* e = syms + i * 12;
      if (e + 12 > end) break;
      uint32_t n_strx, n_value;
      uint8_t n_type, n_sect;
      int16_t n_desc;
      memcpy(&n_strx, e, 4);
      memcpy(&n_type, e + 4, 1);
      memcpy(&n_sect, e + 5, 1);
      memcpy(&n_desc, e + 6, 2);
      memcpy(&n_value, e + 8, 4);
      if (n_type & N_STAB) continue;
      if (n_strx >= strsize) continue;
      std::string name(strs + n_strx, strnlen(strs + n_strx, strsize - n_strx));
      if (name.empty()) continue;

      if ((n_type & N_TYPE) == N_UNDF) {
        Import im;
        im.name = name;
        uint8_t ord = LibraryOrdinal(uint16_t(n_desc));
        im.dylib = (ord >= 1 && ord <= ordinal_dylibs.size())
                       ? ordinal_dylibs[ord - 1]
                       : "(dynamic lookup)";
        imports_.push_back(im);
      } else if ((n_type & N_TYPE) == N_SECT) {
        Export ex;
        ex.name = name;
        ex.addr = n_value & ~1u;
        ex.thumb = (uint16_t(n_desc) & N_ARM_THUMB_DEF) != 0;
        exports_.push_back(ex);
      }
    }
  }
  return true;
}

const Section* MachOImage::FindSection(const std::string& seg,
                                       const std::string& name) const {
  for (const auto& s : sections_)
    if (s.segment == seg && s.name == name) return &s;
  return nullptr;
}

size_t MachOImage::thumb_count() const {
  size_t n = 0;
  for (const auto& e : exports_) n += e.thumb ? 1 : 0;
  return n;
}

bool MachOImage::Map() {
  if (segments_.empty()) { error_ = "nothing to map"; return false; }

  // The image loads at its own link address and nowhere else, and that is a
  // property of the file rather than a preference. These binaries are non-PIE
  // with an empty rebase table -- 0 rebase opcodes, 0 local relocations -- so
  // nothing records which words are pointers, and an absolute pointer in
  // __DATA cannot be corrected after the fact. Only a zero slide leaves it
  // right.
  //
  // What makes that affordable is the lifter: it folds every literal-pool load
  // into a constant, and __TEXT,__text is the only section that lies below the
  // 64 KB floor every desktop OS puts on low mappings. So the bytes down there
  // have no run-time reader, the region is simply left unmapped, and the OS's
  // own refusal to hand it out becomes a guard page for free -- anything that
  // does read it faults immediately instead of quietly reading a zero.
  uint32_t lo = 0xFFFFFFFFu, hi = 0;
  for (const auto& s : segments_) {
    if (s.vmsize == 0 || s.name == "__PAGEZERO") continue;
    lo = std::min(lo, s.vmaddr);
    hi = std::max(hi, s.vmaddr + s.vmsize);
  }
  if (hi <= lo) { error_ = "empty vm range"; return false; }
  link_base_ = lo;

  const uint32_t floor = lo > kLowAddressFloor ? lo : kLowAddressFloor;
  if (hi <= floor) { error_ = "the whole image sits below the low floor"; return false; }
  const size_t span = hi - floor;

#if defined(_WIN32)
  void* region = VirtualAlloc(reinterpret_cast<LPVOID>(uintptr_t(floor)), span,
                              MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
  void* region = mmap(reinterpret_cast<void*>(uintptr_t(floor)), span,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (region == MAP_FAILED) region = nullptr;
#endif
  if (region != reinterpret_cast<void*>(uintptr_t(floor))) {
    error_ = "could not map the image at its link address; it cannot be slid, "
             "because the file records no relocations";
    return false;
  }

  // Zero, and checked rather than computed. If this is ever nonzero the image
  // is in the wrong place and every absolute pointer in it is wrong with it.
  slide_ = 0;

  for (auto& s : segments_) {
    if (s.filesize == 0 || s.name == "__PAGEZERO") continue;
    if (slice_ + s.fileoff + s.filesize > file_.size()) {
      error_ = "segment " + s.name + " runs past the end of the file";
      return false;
    }
    // A segment straddling the floor is copied from the floor up; the part
    // below is the code nothing reads.
    uint32_t from = s.vmaddr;
    uint32_t skip = 0;
    if (from < floor) {
      skip = floor - from;
      if (skip >= s.filesize) { s.mapped = nullptr; continue; }
      from = floor;
    }
    uint8_t* dst = reinterpret_cast<uint8_t*>(uintptr_t(from));
    memcpy(dst, file_.data() + slice_ + s.fileoff + skip, s.filesize - skip);
    s.mapped = dst;
  }
  return true;
}

void MachOImage::Bind(const std::string& symbol, void* addr) {
  for (auto& im : imports_)
    if (im.name == symbol) im.bound = addr;
}

}  // namespace arc
