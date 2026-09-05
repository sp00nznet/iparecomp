// The Objective-C half of the app, answered by a runtime rather than lifted.
//
// This is the load-bearing shortcut of the whole design. `objc_msgSend` is the
// most-executed function in any iOS binary and its entire job is a runtime
// lookup, so lifting it would be pointless even where it is possible. Instead
// it is a shim boundary: the lifted code calls in here with the guest's
// registers exactly as it arranged them, this finds the method, and control
// goes back into lifted code at the implementation's address.
//
// What makes it tractable is that none of the class table is reverse
// engineered. The ObjC 2.0 ABI writes the whole thing into __DATA in a
// documented layout, so it is read. Canabalt's 49 classes and 602 methods come
// straight out of __objc_classlist and __objc_catlist, and every one of those
//602 implementations is an address inside the binary -- which is to say,
// lifted code.
//
// Where it stops is equally well defined. A class that inherits from NSObject
// has a zero in its superclass field and a bind entry naming
// `_OBJC_CLASS_$_NSObject` pointing at it, so the exact point at which the
// class graph leaves the binary is a fact the file states. That boundary is
// the framework work list, and it is reported rather than guessed at.
#pragma once

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "arm32_context.h"
#include "macho_image.h"

namespace arc {

struct ObjcMethod {
  std::string selector;
  // The address the method list holds for the name. A SEL in this ABI *is* a
  // pointer to the selector's characters -- the real runtime uniques them at
  // load time, and nothing here does, so what the method list points at and
  // what a selector reference points at are the same string.
  uint32_t selector_addr = 0;
  uint32_t imp = 0;
  bool from_category = false;
};

struct ObjcClass {
  uint32_t addr = 0;        // the class_t itself, which is also its identity
  uint32_t isa = 0;         // its metaclass, where class methods live
  uint32_t superclass = 0;  // zero when the superclass is not in this binary
  std::string name;
  // The symbol a bind entry writes into the superclass field. Non-empty
  // exactly when `superclass` is zero and the chain leaves the binary.
  std::string external_super;
  bool meta = false;
  uint32_t instance_size = 0;  // class_ro_t's instanceSize, for +alloc
  std::vector<ObjcMethod> methods;
};

// A selector the binary sends that no class in the binary implements.
//
// Which *receiver* a given send has is not a static fact -- that is the whole
// reason objc_msgSend is not lifted -- so this cannot be attributed to a
// particular framework class. What it can say exactly is which selectors have
// no implementation anywhere in the image, and those are precisely the ones a
// framework has to answer.

class ObjcRuntime {
 public:
  // Reads the class table out of the mapped image. The image must already be
  // mapped: guest pointers are host pointers here as everywhere else.
  bool Init(const MachOImage& img);

  // The implementation of `selector` for an object whose isa is `cls`,
  // following the superclass chain, or zero. `cls` may be a metaclass, which
  // is what makes a class method no different from an instance one.
  uint32_t Lookup(uint32_t cls, const char* selector) const;

  const ObjcClass* ClassAt(uint32_t addr) const;

  // Walk up from `cls` to the class whose superclass is not in this binary,
  // and return it. That is where a lookup runs out and the host takes over,
  // and its `external_super` names the framework class that must answer.
  const ObjcClass* Boundary(uint32_t cls) const;
  const std::vector<ObjcClass>& classes() const { return classes_; }

  // Selectors the binary sends that nothing in it implements: the framework
  // contract, measured rather than guessed.
  const std::vector<std::string>& unanswered() const { return unanswered_; }
  // Selectors it sends that its own classes do implement.
  size_t answered() const { return answered_; }
  size_t referenced() const { return unanswered_.size() + answered_; }
  size_t method_count() const { return resolved_.size(); }
  const std::string& error() const { return error_; }

 private:
  bool ReadClass(const MachOImage& img, uint32_t addr, bool meta);
  void MergeCategories(const MachOImage& img);
  void Flatten();

  std::vector<ObjcClass> classes_;
  std::unordered_map<uint32_t, size_t> by_addr_;
  // (class, selector) -> imp, with the superclass chain already walked, so a
  // send is one lookup rather than a walk per message.
  std::unordered_map<std::string, uint32_t> resolved_;
  std::vector<std::string> unanswered_;
  size_t answered_ = 0;
  std::string error_;
};

// The process-wide runtime the lifted code's `objc_msgSend` reaches.
ObjcRuntime& Objc();

// Keep going when a framework class has no implementation for a selector,
// answering nil and writing it down, rather than stopping at the first one.
//
// This is a measuring instrument, not a way to run the game. One permissive
// run enumerates everything the startup path asks a framework for, which is
// the difference between learning the contract in one pass and learning it one
// rebuild at a time. Nil is a legitimate answer in Objective-C, so a lot of
// code survives it -- and where it does not, that is worth knowing too.
void SetPermissive(bool on);

// Every (class, selector) answered with nil because nothing implemented it,
// in the order first seen.
const std::vector<std::pair<std::string, std::string>>& MissingMessages();

// Points the guest's objc_msgSend stubs at this runtime. After this, lifted
// code that calls objc_msgSend dispatches into other lifted code.
void InstallObjcRuntime(const MachOImage& img);

}  // namespace arc
