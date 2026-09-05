// A 32-bit ARM Mach-O, mapped and inspected.
//
// The shape of the problem differs from ELF in three ways that matter here.
//
// Imports are not one flat table. Every undefined symbol carries a *library
// ordinal* in its n_desc field naming which dylib is expected to provide it,
// so the work list can be grouped by framework without guessing from name
// prefixes the way the ELF side has to.
//
// Code addresses are absolute, not position-independent. These binaries were
// linked to load at a fixed address and dyld slid them only if it had to, so
// __TEXT vmaddr is meaningful and a lifted literal-pool constant is a real
// address in the original layout. The loader records the slide so the emitter
// can express those as image_base + constant.
//
// And __TEXT may simply be encrypted. A FairPlay binary has an
// LC_ENCRYPTION_INFO with cryptid=1 and its text section is ciphertext; there
// is nothing to load and nothing to lift, so that is checked before anything
// else and reported as a first-class state rather than a parse failure.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace arc {

struct Section {
  std::string segment, name;
  uint32_t addr = 0, size = 0, fileoff = 0;
};

struct Segment {
  std::string name;
  uint32_t vmaddr = 0, vmsize = 0, fileoff = 0, filesize = 0;
  uint32_t initprot = 0, maxprot = 0;
  void* mapped = nullptr;
};

struct Import {
  std::string name;
  std::string dylib;     // resolved from the symbol's library ordinal
  uint32_t stub = 0;     // address of its stub, when one was found
  void* bound = nullptr; // what the shim supplied, or null while outstanding
};

struct Export {
  std::string name;
  uint32_t addr = 0;
  bool thumb = false;    // N_ARM_THUMB_DEF -- the emitter must honour this
};

class MachOImage {
 public:
  // Reads the file, picks a 32-bit ARM slice, and parses its load commands.
  // Does not map anything; call Map() for that. Returns false and fills
  // error() on a malformed file, an unsupported architecture, or a slice whose
  // __TEXT is still encrypted.
  bool Load(const std::string& path, const std::string& want_arch = "");

  // Maps the image at its own link address -- not somewhere convenient. The
  // file records no relocations, so it cannot be slid, and Map() fails rather
  // than placing it somewhere every absolute pointer in it would be wrong.
  // The first 64 KB is left unmapped: no desktop OS will hand it out, and
  // after the lifter folds literal-pool loads nothing reads it. Guest pointers
  // become host pointers from here on.
  bool Map();

  // Binds one import to a host address. Everything still null after the shim
  // has had its turn is the port's outstanding work list.
  void Bind(const std::string& symbol, void* addr);

  const std::vector<Segment>& segments() const { return segments_; }
  const std::vector<Section>& sections() const { return sections_; }
  const std::vector<Import>& imports() const { return imports_; }
  const std::vector<Export>& exports() const { return exports_; }
  const std::vector<std::string>& dylibs() const { return dylibs_; }

  const Section* FindSection(const std::string& seg, const std::string& name) const;

  bool encrypted() const { return encrypted_; }
  uint32_t entry() const { return entry_; }
  // Where the image was linked, which after a successful Map() is also where
  // it is. This is what a lifted program wants as its `image_base`.
  uint32_t link_base() const { return link_base_; }
  // Always zero after Map() succeeds. Kept because a nonzero value is the
  // single clearest way to say that something has gone wrong.
  uint32_t slide() const { return slide_; }
  const std::string& arch() const { return arch_; }
  const std::string& error() const { return error_; }

  // How many exported functions are Thumb. A binary that is entirely one
  // instruction set is a materially easier first lift, so this is worth
  // knowing before committing to a target.
  size_t thumb_count() const;

 private:
  std::vector<uint8_t> file_;
  size_t slice_ = 0;
  std::vector<Segment> segments_;
  std::vector<Section> sections_;
  std::vector<Import> imports_;
  std::vector<Export> exports_;
  std::vector<std::string> dylibs_;
  std::string arch_, error_;
  uint32_t entry_ = 0, slide_ = 0, link_base_ = 0;
  bool encrypted_ = false;

  // The lowest address a desktop OS will hand out: Windows reserves the first
  // 64 KB as the null-pointer partition, and Linux's vm.mmap_min_addr defaults
  // to the same.
  static constexpr uint32_t kLowAddressFloor = 0x10000;
};

}  // namespace arc
