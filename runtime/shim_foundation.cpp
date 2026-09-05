// NSObject and the few Foundation and UIKit entry points the startup path
// needs before the game's own code gets a turn.
//
// The aim here is not a Foundation. It is to get from `main` into
// `applicationDidFinishLaunching:` -- which is lifted code -- so that what the
// game does next becomes an observed fact rather than a guess. Everything past
// that point reports itself.
#include <cstdio>
#include <cstring>

#include "arc_mem.h"
#include "arm32_context.h"
#include "objc_host.h"
#include "objc_runtime.h"

namespace arc {
namespace {

// A CFConstantString: isa, flags, the bytes, the length. The compiler emits
// one of these for every `@"..."` and they sit in __DATA,__cfstring.
constexpr uint32_t kCFStringChars = 8;

const char* CFStringChars(uint32_t s) {
  if (!s) return nullptr;
  const uint32_t p = ARC_LD32(s + kCFStringChars);
  return p ? reinterpret_cast<const char*>(uintptr_t(p)) : nullptr;
}

// ponytail: retain, release and autorelease all return self and count
// nothing. That is consistent with the allocator, which never reuses memory
// either -- so an object whose count reached zero would keep working anyway.
// The ceiling is a session long enough to exhaust the arena, and the upgrade
// is a real free list plus a real count, together or not at all.
// r0 already holds self, which is what all three return.
void RetainLike(Arm32Ctx*) {}
void VoidMethod(Arm32Ctx* c) { ARC_W(c, 0, 0); }
void SelfMethod(Arm32Ctx*) {}

void Alloc(Arm32Ctx* c) {
  // The receiver of +alloc is the class object itself.
  ARC_W(c, 0, HostAllocInstance(ARC_R(c, 0)));
}

void New(Arm32Ctx* c) { Alloc(c); }

void ClassOf(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  ARC_W(c, 0, self ? ARC_LD32(self) : 0);
}

void RespondsToSelector(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  const uint32_t sel = ARC_R(c, 2);
  const uint32_t cls = self ? ARC_LD32(self) : 0;
  const char* name = sel ? reinterpret_cast<const char*>(uintptr_t(sel)) : nullptr;
  const bool yes = cls && name &&
                   (Objc().Lookup(cls, name) || LookupHostMethod(cls, name));
  ARC_W(c, 0, yes ? 1 : 0);
}

void IsKindOfClass(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  const uint32_t want = ARC_R(c, 2);
  uint32_t cursor = self ? ARC_LD32(self) : 0;
  int guard = 0;
  while (cursor && guard++ < 64) {
    if (cursor == want) {
      ARC_W(c, 0, 1);
      return;
    }
    const ObjcClass* k = Objc().ClassAt(cursor);
    cursor = k ? k->superclass : ARC_LD32(cursor + 4);
  }
  ARC_W(c, 0, 0);
}

// --- UIApplicationMain -----------------------------------------------------

uint32_t GuestClassNamed(const char* name) {
  if (!name) return 0;
  for (const auto& k : Objc().classes())
    if (!k.meta && k.name == name) return k.addr;
  return 0;
}

void SendSelector(Arm32Ctx* c, uint32_t receiver, const char* selector,
                  uint32_t arg) {
  const uint32_t cls = receiver ? ARC_LD32(receiver) : 0;
  if (!cls) return;
  ARC_W(c, 0, receiver);
  ARC_W(c, 2, arg);
  if (const uint32_t imp = Objc().Lookup(cls, selector)) {
    arc_dispatch(c, imp);
    return;
  }
  if (const ArcCtxFn fn = LookupHostMethod(cls, selector)) fn(c);
}

// UIApplicationMain(argc, argv, principalClassName, delegateClassName).
//
// The real one builds an application object, loads the nib, and runs the
// event loop. This does the part that matters for bring-up: find the delegate
// class the fourth argument names, make one, and tell it the application
// finished launching. That hands control to lifted code, which is the point.
void UIApplicationMainShim(Arm32Ctx* c) {
  const char* name = CFStringChars(ARC_R(c, 3));
  if (!name) {
    arc_trap(c, "UIApplicationMain: the delegate class name is not readable");
    return;
  }
  const uint32_t cls = GuestClassNamed(name);
  if (!cls) {
    char msg[160];
    std::snprintf(msg, sizeof msg,
                  "UIApplicationMain: no class named %s in this binary", name);
    arc_trap(c, msg);
    return;
  }
  std::printf("  UIApplicationMain: delegate is %s\n", name);

  const uint32_t app = HostAllocInstance(HostClass("UIApplication", "NSObject"));
  const uint32_t delegate = HostAllocInstance(cls);
  if (!delegate) {
    arc_trap(c, "UIApplicationMain: could not allocate the delegate");
    return;
  }
  SendSelector(c, delegate, "init", 0);
  const uint32_t inited = ARC_R(c, 0) ? ARC_R(c, 0) : delegate;
  SendSelector(c, inited, "applicationDidFinishLaunching:", app);
  ARC_W(c, 0, 0);
}

struct HostSel {
  const char* cls;
  bool meta;
  const char* sel;
  ArcCtxFn fn;
};

const HostSel kMethods[] = {
    {"NSObject", true, "alloc", Alloc},
    {"NSObject", true, "new", New},
    {"NSObject", true, "class", SelfMethod},
    {"NSObject", false, "init", SelfMethod},
    {"NSObject", false, "self", SelfMethod},
    {"NSObject", false, "retain", RetainLike},
    {"NSObject", false, "autorelease", RetainLike},
    {"NSObject", false, "release", VoidMethod},
    {"NSObject", false, "dealloc", VoidMethod},
    {"NSObject", false, "drain", VoidMethod},
    {"NSObject", false, "class", ClassOf},
    {"NSObject", false, "respondsToSelector:", RespondsToSelector},
    {"NSObject", false, "isKindOfClass:", IsKindOfClass},
    {"NSObject", false, "isMemberOfClass:", IsKindOfClass},
};

}  // namespace

void InstallFoundationClasses() {
  HostClass("NSObject", nullptr);
  for (const auto& m : kMethods) {
    HostClass(m.cls, m.cls == std::string("NSObject") ? nullptr : "NSObject");
    HostMethod(m.cls, m.meta, m.sel, m.fn);
  }
}

size_t InstallUIKitShims(const MachOImage& img) {
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    if (im.name == "_UIApplicationMain") {
      arc_register_ctx_native(im.stub, "UIApplicationMain",
                              UIApplicationMainShim);
      ++claimed;
    }
  }
  return claimed;
}

}  // namespace arc
