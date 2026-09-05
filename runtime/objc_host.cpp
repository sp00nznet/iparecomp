#include "objc_host.h"

#include <cstring>
#include <map>
#include <string>
#include <unordered_map>

#include "arc_mem.h"
#include "objc_runtime.h"

namespace arc {
namespace {

// class_t and class_ro_t, laid out exactly as the ABI defines them, so that
// the same reader walks host and guest classes alike.
constexpr uint32_t kClassSize = 20;
constexpr uint32_t kRoSize = 40;
constexpr uint32_t kRoIsMeta = 0x1;

struct HostClassInfo {
  std::string name;
  uint32_t super = 0;
  bool meta = false;
  std::unordered_map<std::string, ArcCtxFn> methods;
  // Methods that live in the lifted binary rather than here, which is what a
  // category on a framework class produces.
  std::unordered_map<std::string, uint32_t> guest_methods;
};

std::map<uint32_t, HostClassInfo>& Classes() {
  static std::map<uint32_t, HostClassInfo> m;
  return m;
}

// name -> its class object; the metaclass is looked up by the same name with
// the `meta` flag, so both live in one index.
std::map<std::string, uint32_t>& ByName() {
  static std::map<std::string, uint32_t> m;
  return m;
}

std::map<std::string, uint32_t>& MetaByName() {
  static std::map<std::string, uint32_t> m;
  return m;
}

void W(uint32_t addr, uint32_t value) { ARC_ST32(addr, value); }

uint32_t MakeClassObject(const std::string& name, uint32_t super, bool meta,
                         uint32_t isa, uint32_t instance_size) {
  const uint32_t ro = arc_guest_alloc(kRoSize, 8);
  const uint32_t obj = arc_guest_alloc(kClassSize, 8);
  const uint32_t str = arc_guest_strdup(name.c_str());
  if (!ro || !obj || !str) return 0;
  std::memset(reinterpret_cast<void*>(uintptr_t(ro)), 0, kRoSize);
  std::memset(reinterpret_cast<void*>(uintptr_t(obj)), 0, kClassSize);
  W(ro + 0, meta ? kRoIsMeta : 0);
  W(ro + 8, instance_size);
  W(ro + 16, str);
  W(obj + 0, isa);
  W(obj + 4, super);
  W(obj + 16, ro);
  HostClassInfo info;
  info.name = name;
  info.super = super;
  info.meta = meta;
  Classes()[obj] = info;
  return obj;
}

}  // namespace

uint32_t HostClass(const char* name, const char* super) {
  auto it = ByName().find(name);
  if (it != ByName().end()) return it->second;

  uint32_t super_cls = 0, super_meta = 0;
  if (super && *super) {
    super_cls = HostClass(super, nullptr);
    super_meta = MetaByName()[super];
  }
  // The metaclass first: a class object's isa is its metaclass, so it has to
  // exist before the class can point at it.
  const uint32_t meta = MakeClassObject(name, super_meta, true, 0, kClassSize);
  // An instance of a host class carries just its isa unless something asks
  // for more; the guest never allocates one without going through +alloc.
  const uint32_t cls = MakeClassObject(name, super_cls, false, meta, 16);
  if (meta) W(meta + 0, meta);  // a metaclass's isa is the root metaclass
  ByName()[name] = cls;
  MetaByName()[name] = meta;
  return cls;
}

void HostMethod(const char* cls, bool meta, const char* selector, ArcCtxFn fn) {
  const uint32_t obj = meta ? MetaByName()[cls] : ByName()[cls];
  if (!obj) return;
  Classes()[obj].methods[selector] = fn;
}

uint32_t HostClassByName(const char* name, bool meta) {
  if (!name || !*name) return 0;
  auto& index = meta ? MetaByName() : ByName();
  auto it = index.find(name);
  return it == index.end() ? 0 : it->second;
}

const char* HostClassName(uint32_t cls) {
  auto it = Classes().find(cls);
  return it == Classes().end() ? nullptr : it->second.name.c_str();
}

void HostGuestMethod(const char* cls, bool meta, const char* selector,
                     uint32_t imp) {
  HostClass(cls, std::string(cls) == "NSObject" ? nullptr : "NSObject");
  const uint32_t obj = meta ? MetaByName()[cls] : ByName()[cls];
  if (obj) Classes()[obj].guest_methods[selector] = imp;
}

namespace {

// Where a lookup on `cls` should start among the host classes: `cls` itself if
// it is one, otherwise the framework class the guest chain runs out at.
uint32_t HostStart(uint32_t cls) {
  if (Classes().count(cls)) return cls;
  const ObjcClass* boundary = Objc().Boundary(cls);
  if (!boundary || boundary->external_super.empty()) return 0;
  auto& index = boundary->meta ? MetaByName() : ByName();
  auto it = index.find(boundary->external_super);
  return it == index.end() ? 0 : it->second;
}

}  // namespace

uint32_t LookupHostImp(uint32_t cls, const char* selector) {
  if (!selector) return 0;
  uint32_t cursor = HostStart(cls);
  int guard = 0;
  while (cursor && guard++ < 32) {
    auto it = Classes().find(cursor);
    if (it == Classes().end()) return 0;
    auto m = it->second.guest_methods.find(selector);
    if (m != it->second.guest_methods.end()) return m->second;
    cursor = it->second.super;
  }
  return 0;
}

ArcCtxFn LookupHostMethod(uint32_t cls, const char* selector) {
  if (!selector) return nullptr;
  uint32_t cursor = HostStart(cls);
  int guard = 0;
  while (cursor && guard++ < 32) {
    auto it = Classes().find(cursor);
    if (it == Classes().end()) return nullptr;
    auto m = it->second.methods.find(selector);
    if (m != it->second.methods.end()) return m->second;
    cursor = it->second.super;
  }
  return nullptr;
}

uint32_t HostAllocInstance(uint32_t cls) {
  uint32_t size = 16;
  if (const ObjcClass* k = Objc().ClassAt(cls)) {
    // A class object is the metaclass's instance, so +alloc on a guest class
    // wants the *class's* instance size, not the metaclass's.
    size = k->instance_size ? k->instance_size : 16;
  } else if (Classes().count(cls)) {
    size = ARC_LD32(ARC_LD32(cls + 16) + 8);
  }
  if (size < 4) size = 4;
  const uint32_t obj = arc_guest_alloc(size, 16);
  if (!obj) return 0;
  std::memset(reinterpret_cast<void*>(uintptr_t(obj)), 0, size);
  W(obj, cls);
  return obj;
}

size_t BindImportSlots(const MachOImage& img) {
  size_t filled = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const uint32_t slot : im.slots) {
      W(slot, im.stub);
      ++filled;
    }
  }
  return filled;
}

size_t BindHostClasses(const MachOImage& img) {
  static const char kClass[] = "_OBJC_CLASS_$_";
  static const char kMeta[] = "_OBJC_METACLASS_$_";
  size_t filled = 0;
  for (const auto& b : img.bindings()) {
    const bool meta = b.symbol.rfind(kMeta, 0) == 0;
    const bool cls = b.symbol.rfind(kClass, 0) == 0;
    if (!meta && !cls) continue;
    const std::string name =
        b.symbol.substr(meta ? sizeof(kMeta) - 1 : sizeof(kClass) - 1);
    // Every framework class gets an object whether or not a method is ever
    // attached. An empty class that answers nothing still beats a zero, which
    // silently swallows every message sent to it.
    HostClass(name.c_str(), name == "NSObject" ? nullptr : "NSObject");
    const uint32_t obj = meta ? MetaByName()[name] : ByName()[name];
    if (!obj) continue;
    W(b.address, obj);
    ++filled;
  }
  return filled;
}

}  // namespace arc
