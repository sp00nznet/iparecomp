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
constexpr uint32_t LC_DYLD_INFO = 0x22;
constexpr uint32_t LC_DYLD_INFO_ONLY = 0x80000022;
constexpr uint32_t LC_MAIN = 0x80000028;

// Section types, in the low byte of a section's flags.
constexpr uint32_t S_NON_LAZY_SYMBOL_POINTERS = 0x6;
constexpr uint32_t S_LAZY_SYMBOL_POINTERS = 0x7;
constexpr uint32_t S_SYMBOL_STUBS = 0x8;

// An indirect symbol table entry that names no symbol.
constexpr uint32_t INDIRECT_SYMBOL_LOCAL = 0x80000000;
constexpr uint32_t INDIRECT_SYMBOL_ABS = 0x40000000;

// The dyld bind opcodes. A tiny stack machine whose whole job is to say
// "write the address of symbol S into segment G at offset O".
constexpr uint8_t BIND_OPCODE_MASK = 0xF0;
constexpr uint8_t BIND_IMMEDIATE_MASK = 0x0F;
constexpr uint8_t BIND_OPCODE_DONE = 0x00;
constexpr uint8_t BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10;
constexpr uint8_t BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20;
constexpr uint8_t BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30;
constexpr uint8_t BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40;
constexpr uint8_t BIND_OPCODE_SET_TYPE_IMM = 0x50;
constexpr uint8_t BIND_OPCODE_SET_ADDEND_SLEB = 0x60;
constexpr uint8_t BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70;
constexpr uint8_t BIND_OPCODE_ADD_ADDR_ULEB = 0x80;
constexpr uint8_t BIND_OPCODE_DO_BIND = 0x90;
constexpr uint8_t BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0;
constexpr uint8_t BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0;
constexpr uint8_t BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0;

uint64_t Uleb(const uint8_t*& p, const uint8_t* end) {
  uint64_t result = 0;
  int shift = 0;
  while (p < end) {
    const uint8_t b = *p++;
    if (shift < 64) result |= uint64_t(b & 0x7F) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
  }
  return result;
}

void SkipSleb(const uint8_t*& p, const uint8_t* end) {
  while (p < end && (*p++ & 0x80)) {
  }
}

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
  uint32_t indirect_off = 0, nindirect = 0;
  uint32_t bind_off = 0, bind_size = 0, lazy_off = 0, lazy_size = 0;

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
        memcpy(&sec.flags, q + 56, 4);
        memcpy(&sec.reserved1, q + 60, 4);
        memcpy(&sec.reserved2, q + 64, 4);
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
    } else if (cmd == LC_DYSYMTAB) {
      memcpy(&indirect_off, p + 8 + 12 * 4, 4);
      memcpy(&nindirect, p + 8 + 13 * 4, 4);
    } else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
      memcpy(&bind_off, p + 16, 4);
      memcpy(&bind_size, p + 20, 4);
      memcpy(&lazy_off, p + 32, 4);
      memcpy(&lazy_size, p + 36, 4);
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

    // Which stub address stands for which import. A stub section carries its
    // first index into the indirect symbol table and its stride, so entry i is
    // indirect symbol reserved1+i, which is an index into the symbol table.
    // No bind opcodes are needed for this half.
    if (nindirect && indirect_off) {
      std::map<std::string, size_t> by_name;
      for (size_t k = 0; k < imports_.size(); ++k) by_name[imports_[k].name] = k;
      const uint8_t* indirect = base + indirect_off;
      for (const auto& sec : sections_) {
        const uint32_t type = sec.flags & 0xFF;
        const bool is_stub = type == S_SYMBOL_STUBS;
        const bool is_ptr = type == S_LAZY_SYMBOL_POINTERS ||
                            type == S_NON_LAZY_SYMBOL_POINTERS;
        if (!is_stub && !is_ptr) continue;
        const uint32_t stride = is_stub ? sec.reserved2 : 4;
        if (!stride) continue;
        for (uint32_t k = 0; k < sec.size / stride; ++k) {
          const uint32_t slot = sec.reserved1 + k;
          if (slot >= nindirect) break;
          uint32_t sym;
          memcpy(&sym, indirect + slot * 4, 4);
          if (sym & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
          if (sym >= nsyms) continue;
          uint32_t strx;
          memcpy(&strx, syms + sym * 12, 4);
          if (strx >= strsize) continue;
          const std::string nm(strs + strx, strnlen(strs + strx, strsize - strx));
          auto it = by_name.find(nm);
          if (it == by_name.end()) continue;
          const uint32_t at = sec.addr + k * stride;
          if (is_stub) {
            imports_[it->second].stub = at;
          } else {
            if (!imports_[it->second].slot) imports_[it->second].slot = at;
            imports_[it->second].slots.push_back(at);
          }
        }
      }
    }
  }

  ParseBindings(base, bind_off, bind_size, false);
  ParseBindings(base, lazy_off, lazy_size, true);
  return true;
}

// The dyld bind opcodes: a small stack machine that writes symbol addresses
// into pointer-sized words. Interpreting it is the only way to learn which
// external symbol belongs at which address, because a non-PIE binary of this
// era carries no relocations at all -- see Map().
void MachOImage::ParseBindings(const uint8_t* base, uint32_t off, uint32_t size,
                               bool lazy) {
  if (!off || !size) return;
  const uint8_t* p = base + off;
  const uint8_t* end = p + size;

  std::string symbol;
  std::string dylib = "(dynamic lookup)";
  uint32_t seg = 0;
  uint64_t offset = 0;

  auto record = [&]() {
    if (symbol.empty() || seg >= segments_.size()) return;
    Binding b;
    b.address = uint32_t(segments_[seg].vmaddr + offset);
    b.symbol = symbol;
    b.dylib = dylib;
    b.lazy = lazy;
    bindings_.push_back(b);
  };

  while (p < end) {
    const uint8_t byte = *p++;
    const uint8_t op = byte & BIND_OPCODE_MASK;
    const uint8_t imm = byte & BIND_IMMEDIATE_MASK;
    switch (op) {
      case BIND_OPCODE_DONE:
        // In the lazy table this ends one entry, not the whole table.
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        if (imm >= 1 && imm <= dylibs_.size())
          dylib = ShortDylib(dylibs_[imm - 1]);
        break;
      case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
        const uint64_t n = Uleb(p, end);
        if (n >= 1 && n <= dylibs_.size()) dylib = ShortDylib(dylibs_[n - 1]);
        break;
      }
      case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        dylib = "(special)";
        break;
      case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
        const char* str = reinterpret_cast<const char*>(p);
        const size_t max = size_t(end - p);
        symbol.assign(str, strnlen(str, max));
        p += symbol.size() + 1;
        break;
      }
      case BIND_OPCODE_SET_TYPE_IMM:
        break;
      case BIND_OPCODE_SET_ADDEND_SLEB:
        SkipSleb(p, end);
        break;
      case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
        seg = imm;
        offset = Uleb(p, end);
        break;
      case BIND_OPCODE_ADD_ADDR_ULEB:
        offset += Uleb(p, end);
        break;
      case BIND_OPCODE_DO_BIND:
        record();
        offset += 4;
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        record();
        offset += 4 + Uleb(p, end);
        break;
      case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        record();
        offset += 4 + uint64_t(imm) * 4;
        break;
      case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
        const uint64_t count = Uleb(p, end);
        const uint64_t skip = Uleb(p, end);
        for (uint64_t k = 0; k < count && k < 0x10000; ++k) {
          record();
          offset += 4 + skip;
        }
        break;
      }
      default:
        return;  // an opcode this does not know; stop rather than guess
    }
  }
}

const std::string& MachOImage::BoundSymbolAt(uint32_t address) const {
  static const std::string kNone;
  for (const auto& b : bindings_)
    if (b.address == address) return b.symbol;
  return kNone;
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

void MachOImage::SetImportStub(size_t index, uint32_t address) {
  if (index < imports_.size()) imports_[index].stub = address;
}

void MachOImage::Bind(const std::string& symbol, void* addr) {
  for (auto& im : imports_)
    if (im.name == symbol) im.bound = addr;
}

}  // namespace arc
