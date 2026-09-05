// Classes the host implements, given real class objects in guest memory.
//
// A framework class cannot just be a host-side table. The guest holds class
// objects: it loads one out of `__objc_classrefs`, passes it around, stores it
// as an instance's `isa`, and inherits from it. All of that is 32-bit pointer
// traffic, so `NSObject` has to *exist* at a guest address like any other
// class -- with the same class_t and class_ro_t layout the ABI defines, so
// that the same reader handles both kinds.
//
// What differs is only where the implementation lives. A guest class's method
// list points at lifted code; a host class's methods are C functions in this
// process, held in a table beside the class object rather than inside it.
//
// The empty `__objc_classrefs` slot is why this is needed at all rather than
// merely nice: with nothing bound there the guest loads zero, sends to nil,
// and gets zero back without complaint. `[NSAutoreleasePool alloc]` silently
// does nothing and the failure surfaces much later and somewhere else.
#pragma once

#include <stdint.h>

#include "arm32_context.h"
#include "macho_image.h"

namespace arc {

// The guest address of a host class object, created the first time it is
// asked for. `super` may be null for a root class. The metaclass is made
// alongside, because a class method has to land somewhere.
uint32_t HostClass(const char* name, const char* super);

// Attach an implementation. `meta` selects the metaclass, which is to say a
// `+` method rather than a `-` one.
void HostMethod(const char* cls, bool meta, const char* selector, ArcCtxFn fn);

// Attach a *lifted* implementation to a host class. This is how a category on
// a framework class works: `@interface UIColor (HexColor)` is compiled into
// this binary, so its methods are guest code even though the class they extend
// is not. The address is a guest address, dispatched like any other.
void HostGuestMethod(const char* cls, bool meta, const char* selector,
                     uint32_t imp);

// The lifted implementation for a selector sent to `cls`, or zero.
uint32_t LookupHostImp(uint32_t cls, const char* selector);

// The implementation for a selector sent to `cls`, walking the host
// superclass chain, or null. `cls` is a guest address: either a host class
// object, or a guest class whose chain leaves the binary.
ArcCtxFn LookupHostMethod(uint32_t cls, const char* selector);

// A host class object by name, or zero if there is no such class. `meta`
// selects the metaclass.
uint32_t HostClassByName(const char* name, bool meta);

// The name of a host class object, or null if that address is not one.
const char* HostClassName(uint32_t cls);

// Fill every `_OBJC_CLASS_$_` and `_OBJC_METACLASS_$_` bind site with the
// address of the matching host class object, creating classes as needed. This
// is what dyld would have done, and without it those slots read zero.
// Returns how many sites were filled.
size_t BindHostClasses(const MachOImage& img);

// Point every import's pointer slot at its own stub.
//
// An import is reachable two ways and only one of them was wired. `bl` goes
// straight to the stub, which the native table answers. But a PIC call loads
// the *slot* and branches to whatever it holds -- and dyld would have written
// an address there. Nothing did, so it held zero, and `_start`'s tail call to
// `exit` branched to nothing after main had run to completion.
//
// What goes in the slot is the stub's own address, deliberately: a guest
// address is 32 bits and a host function pointer is not, so the slot can never
// hold the shim itself. Branching to the stub arrives at the same native table
// the direct call uses.
size_t BindImportSlots(const MachOImage& img);

// Allocate an instance of `cls`, zeroed, with its isa set. Guest memory, so
// the address fits in the register the guest will keep it in.
uint32_t HostAllocInstance(uint32_t cls);

// NSObject and the handful of Foundation classes the startup path needs.
void InstallFoundationClasses();

}  // namespace arc
