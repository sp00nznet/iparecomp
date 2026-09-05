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

// The implementation for a selector sent to `cls`, walking the host
// superclass chain, or null. `cls` is a guest address: either a host class
// object, or a guest class whose chain leaves the binary.
ArcCtxFn LookupHostMethod(uint32_t cls, const char* selector);

// The name of a host class object, or null if that address is not one.
const char* HostClassName(uint32_t cls);

// Fill every `_OBJC_CLASS_$_` and `_OBJC_METACLASS_$_` bind site with the
// address of the matching host class object, creating classes as needed. This
// is what dyld would have done, and without it those slots read zero.
// Returns how many sites were filled.
size_t BindHostClasses(const MachOImage& img);

// Allocate an instance of `cls`, zeroed, with its isa set. Guest memory, so
// the address fits in the register the guest will keep it in.
uint32_t HostAllocInstance(uint32_t cls);

// NSObject and the handful of Foundation classes the startup path needs.
void InstallFoundationClasses();

}  // namespace arc
