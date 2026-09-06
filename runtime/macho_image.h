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
  // The low byte of flags is the section *type*, which is what says a section
  // holds symbol stubs or symbol pointers. reserved1 is then its first index
  // into the indirect symbol table and reserved2 the stride, which together
  // are how a stub address is turned back into the symbol it stands for.
  uint32_t flags = 0, reserved1 = 0, reserved2 = 0;
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
  // Two guest addresses stand for one import, and they are reached by
  // different instructions. `stub` is code -- what a `bl` targets. `slot` is
  // the data word an indirect call loads before branching. Both must resolve
  // to the same shim.
  uint32_t stub = 0;
  // An import can have more than one pointer slot -- a lazy one and a
  // non-lazy one -- and code reaches it through either. Recording only the
  // first leaves the other holding zero, which is how `_start`'s tail call to
  // `exit` branched to nothing after main had run to completion.
  uint32_t slot = 0;             // the first, for reporting
  std::vector<uint32_t> slots;   // every one, for binding
  void* bound = nullptr; // what the shim supplied, or null while outstanding
};

// One entry of the dyld bind tables: the address of a pointer-sized word that
// dyld would have filled in with `symbol`.
//
// This is how an external Objective-C class reaches the binary. A class whose
// superclass is NSObject has a zero in its superclass field on disk and a bind
// entry naming `_OBJC_CLASS_$_NSObject` that points at it -- so the class graph
// only says where it leaves the binary once these are read.
struct Binding {
  uint32_t address = 0;
  std::string symbol;
  std::string dylib;
  bool lazy = false;
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
  const std::vector<Binding>& bindings() const { return bindings_; }

  // What dyld would have written at `address`, or an empty string. The
  // Objective-C runtime asks this to name the framework class a guest class
  // inherits from, since that field is zero until something binds it.
  const std::string& BoundSymbolAt(uint32_t address) const;

  const Section* FindSection(const std::string& seg, const std::string& name) const;

  // Give an import a guest address to be known by, for the ones the linker
  // gave no stub. An import called only through its pointer slot has no code
  // anywhere in the image, so there is no address to register a shim at until
  // one is invented.
  void SetImportStub(size_t index, uint32_t address);

  bool encrypted() const { return encrypted_; }
  uint32_t entry() const { return entry_; }
  // Where the image was linked, which after a successful Map() is also where
  // it is. This is what a lifted program wants as its `image_base`.
  uint32_t link_base() const { return link_base_; }
  // Always zero after Map() succeeds. Kept because a nonzero value is the
  // single clearest way to say that something has gone wrong.
  uint32_t slide() const { return slide_; }
  const std::string& arch() const { return arch_; }
  // The leaf of the path this image was loaded from. The guest's argv[0]:
  // a binary's own name is a property of the binary, not of the toolkit.
  std::string name() const {
    const size_t slash = path_.find_last_of("/\\");
    return slash == std::string::npos ? path_ : path_.substr(slash + 1);
  }
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
  std::vector<Binding> bindings_;
  void ParseBindings(const uint8_t* base, uint32_t off, uint32_t size,
                     bool lazy);

  std::string arch_, error_, path_;
  uint32_t entry_ = 0, slide_ = 0, link_base_ = 0;
  bool encrypted_ = false;

  // The lowest address a desktop OS will hand out: Windows reserves the first
  // 64 KB as the null-pointer partition, and Linux's vm.mmap_min_addr defaults
  // to the same.
  static constexpr uint32_t kLowAddressFloor = 0x10000;
};

}  // namespace arc
