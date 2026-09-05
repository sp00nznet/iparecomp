#include "objc_runtime.h"

#include "objc_host.h"

#include <cstdio>
#include <cstring>
#include <set>

namespace arc {
namespace {

// class_t, 32-bit ABI.
constexpr uint32_t kClassIsa = 0;
constexpr uint32_t kClassSuper = 4;
constexpr uint32_t kClassRo = 16;
// class_ro_t.
constexpr uint32_t kRoFlags = 0;
constexpr uint32_t kRoInstanceSize = 8;
constexpr uint32_t kRoName = 16;
constexpr uint32_t kRoMethods = 20;
constexpr uint32_t kRoIsMeta = 0x1;
// method_t, and the stride the list declares for itself.
constexpr uint32_t kMethodSize = 12;
// category_t.
constexpr uint32_t kCatName = 0;
constexpr uint32_t kCatClass = 4;
constexpr uint32_t kCatInstanceMethods = 8;
constexpr uint32_t kCatClassMethods = 12;

ObjcRuntime g_objc;
const MachOImage* g_image = nullptr;
bool g_permissive = false;
std::vector<std::pair<std::string, std::string>> g_missing;
std::set<std::string> g_missing_seen;

// Guest pointers are host pointers, but the first 64 KB is deliberately not
// mapped and a malformed table should be refused rather than dereferenced. So
// every read goes through a range the image actually owns.
struct Reader {
  uint32_t lo = 0, hi = 0;

  explicit Reader(const MachOImage& img) {
    for (const auto& s : img.segments()) {
      if (!s.vmsize || s.name == "__PAGEZERO") continue;
      lo = lo ? (s.vmaddr < lo ? s.vmaddr : lo) : s.vmaddr;
      const uint32_t end = s.vmaddr + s.vmsize;
      if (end > hi) hi = end;
    }
    if (lo < 0x10000) lo = 0x10000;  // the floor Map() honours
  }

  bool Has(uint32_t addr, uint32_t n) const {
    return addr >= lo && addr + n > addr && addr + n <= hi;
  }

  uint32_t U32(uint32_t addr) const {
    if (!Has(addr, 4)) return 0;
    uint32_t v;
    memcpy(&v, reinterpret_cast<const void*>(uintptr_t(addr)), 4);
    return v;
  }

  std::string Str(uint32_t addr) const {
    if (!Has(addr, 1)) return std::string();
    const char* p = reinterpret_cast<const char*>(uintptr_t(addr));
    const size_t max = hi - addr;
    return std::string(p, strnlen(p, max < 512 ? max : 512));
  }
};

std::string Key(uint32_t cls, const std::string& sel) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "%08x:", cls);
  return std::string(buf) + sel;
}

// The name a bound symbol carries, without the ABI's prefix.
std::string ClassNameOf(const std::string& symbol) {
  static const char kClass[] = "_OBJC_CLASS_$_";
  static const char kMeta[] = "_OBJC_METACLASS_$_";
  if (symbol.rfind(kMeta, 0) == 0) return symbol.substr(sizeof(kMeta) - 1);
  if (symbol.rfind(kClass, 0) == 0) return symbol.substr(sizeof(kClass) - 1);
  return symbol;
}

}  // namespace

ObjcRuntime& Objc() { return g_objc; }

void SetPermissive(bool on) { g_permissive = on; }

const std::vector<std::pair<std::string, std::string>>& MissingMessages() {
  return g_missing;
}

bool ObjcRuntime::ReadClass(const MachOImage& img, uint32_t addr, bool meta) {
  if (!addr || by_addr_.count(addr)) return true;
  const Reader r(img);
  const uint32_t ro = r.U32(addr + kClassRo);
  if (!ro) return false;

  ObjcClass c;
  c.addr = addr;
  c.isa = r.U32(addr + kClassIsa);
  c.superclass = r.U32(addr + kClassSuper);
  c.name = r.Str(r.U32(ro + kRoName));
  c.instance_size = r.U32(ro + kRoInstanceSize);
  c.meta = meta || (r.U32(ro + kRoFlags) & kRoIsMeta) != 0;
  if (!c.superclass) {
    // Zero does not mean "root class". It means dyld was going to fill this
    // in, and the bind table says with what.
    c.external_super = ClassNameOf(img.BoundSymbolAt(addr + kClassSuper));
  }

  const uint32_t ml = r.U32(ro + kRoMethods);
  if (ml) {
    uint32_t entsize = r.U32(ml);
    uint32_t count = r.U32(ml + 4);
    // Trust the declared stride over the struct size, since a toolchain may
    // pad -- but refuse anything implausible rather than walking off the end.
    if (entsize < kMethodSize || entsize > 64 || count > 4096) {
      entsize = kMethodSize;
      if (count > 4096) count = 0;
    }
    for (uint32_t i = 0; i < count; ++i) {
      const uint32_t e = ml + 8 + i * entsize;
      ObjcMethod m;
      m.selector_addr = r.U32(e);
      m.selector = r.Str(m.selector_addr);
      m.imp = r.U32(e + 8);
      if (!m.selector.empty() && m.imp) c.methods.push_back(m);
    }
  }

  by_addr_[addr] = classes_.size();
  classes_.push_back(c);

  // The metaclass is a class like any other, and it is where class methods
  // live. Reading it is what makes `[Foo alloc]` no different from `[foo bar]`.
  if (!meta && c.isa && c.isa != addr) ReadClass(img, c.isa, true);
  return true;
}

void ObjcRuntime::MergeCategories(const MachOImage& img) {
  const Section* cat = img.FindSection("__DATA", "__objc_catlist");
  if (!cat) return;
  const Reader r(img);
  for (uint32_t i = 0; i < cat->size / 4; ++i) {
    const uint32_t c = r.U32(cat->addr + i * 4);
    if (!c) continue;
    const uint32_t target = r.U32(c + kCatClass);
    // A category on a framework class -- NSString, NSArray -- has a zero here
    // and a bind entry naming it. Those methods belong to a class this binary
    // does not define, so they are recorded as owed rather than merged.
    if (!target || !by_addr_.count(target)) continue;
    for (int pass = 0; pass < 2; ++pass) {
      const uint32_t ml =
          r.U32(c + (pass ? kCatClassMethods : kCatInstanceMethods));
      if (!ml) continue;
      ObjcClass& into = classes_[by_addr_[target]];
      ObjcClass* dst = &into;
      if (pass) {
        auto it = by_addr_.find(into.isa);
        if (it == by_addr_.end()) continue;
        dst = &classes_[it->second];
      }
      uint32_t entsize = r.U32(ml), count = r.U32(ml + 4);
      if (entsize < kMethodSize || entsize > 64 || count > 4096) {
        entsize = kMethodSize;
        if (count > 4096) count = 0;
      }
      for (uint32_t k = 0; k < count; ++k) {
        const uint32_t e = ml + 8 + k * entsize;
        ObjcMethod m;
        m.selector_addr = r.U32(e);
        m.selector = r.Str(m.selector_addr);
        m.imp = r.U32(e + 8);
        m.from_category = true;
        // A category overrides the class's own method, so it goes in front.
        if (!m.selector.empty() && m.imp)
          dst->methods.insert(dst->methods.begin(), m);
      }
    }
  }
}

void ObjcRuntime::Flatten() {
  // Resolve every (class, selector) once, walking the superclass chain
  // nearest-first, so a send is a single lookup rather than a walk. With 49
  // classes this table is small enough that the walk is not worth keeping.
  for (const auto& c : classes_) {
    uint32_t cursor = c.addr;
    int guard = 0;
    while (cursor && guard++ < 64) {
      auto it = by_addr_.find(cursor);
      if (it == by_addr_.end()) break;
      const ObjcClass& up = classes_[it->second];
      for (const auto& m : up.methods)
        resolved_.emplace(Key(c.addr, m.selector), m.imp);
      cursor = up.superclass;
    }
  }
}

bool ObjcRuntime::Init(const MachOImage& img) {
  classes_.clear();
  by_addr_.clear();
  resolved_.clear();
  unanswered_.clear();
  answered_ = 0;

  const Section* list = img.FindSection("__DATA", "__objc_classlist");
  if (!list) {
    error_ = "no __objc_classlist; this binary defines no Objective-C classes";
    return false;
  }
  const Reader r(img);
  for (uint32_t i = 0; i < list->size / 4; ++i) {
    const uint32_t cls = r.U32(list->addr + i * 4);
    if (cls) ReadClass(img, cls, false);
  }
  MergeCategories(img);
  Flatten();

  // What the binary sends that it cannot answer. Which receiver a send has is
  // not a static fact -- that is the whole reason objc_msgSend is a shim
  // boundary rather than something to lift -- so this cannot say which class
  // owes which selector. What it can say exactly is which selectors have no
  // implementation anywhere in the image, and those are the framework
  // contract.
  std::set<std::string> implemented;
  for (const auto& c : classes_)
    for (const auto& m : c.methods) implemented.insert(m.selector);

  const Section* refs = img.FindSection("__DATA", "__objc_selrefs");
  if (refs) {
    std::set<std::string> sels;
    for (uint32_t i = 0; i < refs->size / 4; ++i) {
      const std::string s = r.Str(r.U32(refs->addr + i * 4));
      if (!s.empty()) sels.insert(s);
    }
    for (const auto& s : sels) {
      if (implemented.count(s)) ++answered_;
      else unanswered_.push_back(s);
    }
  }
  return true;
}

uint32_t ObjcRuntime::Lookup(uint32_t cls, const char* selector) const {
  if (!cls || !selector) return 0;
  auto it = resolved_.find(Key(cls, selector));
  return it == resolved_.end() ? 0 : it->second;
}

const ObjcClass* ObjcRuntime::ClassAt(uint32_t addr) const {
  auto it = by_addr_.find(addr);
  return it == by_addr_.end() ? nullptr : &classes_[it->second];
}

const ObjcClass* ObjcRuntime::Boundary(uint32_t cls) const {
  const ObjcClass* c = ClassAt(cls);
  int guard = 0;
  while (c && c->superclass && guard++ < 64) {
    const ObjcClass* up = ClassAt(c->superclass);
    if (!up) break;
    c = up;
  }
  return c;
}

namespace {

// The selector register holds a pointer to the selector's name. The real
// runtime uniques these into opaque SELs at load time; nothing here does, so
// they are still the strings the compiler emitted, which is exactly what the
// method lists point at too.
const char* SelName(uint32_t sel) {
  if (!g_image || !sel) return nullptr;
  static Reader* reader = nullptr;
  if (!reader) reader = new Reader(*g_image);
  if (!reader->Has(sel, 1)) return nullptr;
  return reinterpret_cast<const char*>(uintptr_t(sel));
}

void Send(Arm32Ctx* c, uint32_t receiver, uint32_t cls, uint32_t sel) {
  // A message to nil is not an error: it evaluates to zero and that is load
  // bearing in real Objective-C, not a corner case.
  if (!receiver) {
    ARC_W(c, 0, 0);
    return;
  }
  const char* name = SelName(sel);
  const uint32_t imp = g_objc.Lookup(cls, name);
  if (imp) {
    // Registers are already arranged as the guest left them: receiver in r0,
    // selector in r1, arguments after. The implementation is lifted code.
    arc_dispatch(c, imp);
    return;
  }
  // Not in this binary, so a framework owes it. The host class the chain runs
  // out at is named by the bind table, and its methods are C functions here.
  if (const ArcCtxFn host = LookupHostMethod(cls, name)) {
    host(c);
    return;
  }
  const ObjcClass* k = g_objc.ClassAt(cls);
  const char* where = k ? k->name.c_str() : HostClassName(cls);
  if (!where) {
    const ObjcClass* b = g_objc.Boundary(cls);
    if (b && !b->external_super.empty()) where = b->external_super.c_str();
  }
  if (g_permissive) {
    // Nil, and written down. An Objective-C caller is entitled to a nil
    // answer, so most of the startup path keeps going and the next thing it
    // needs becomes visible in the same run.
    const std::string cn = where ? where : "?";
    const std::string sn = name ? name : "(unreadable selector)";
    if (g_missing_seen.insert(cn + " " + sn).second)
      g_missing.emplace_back(cn, sn);
    ARC_W(c, 0, 0);
    return;
  }
  if (!k) {
    char msg[256];
    std::snprintf(msg, sizeof msg, "objc_msgSend: %s does not respond to %s",
                  where ? where : "an unknown class",
                  name ? name : "(unreadable selector)");
    arc_trap(c, msg);
    return;
  }
  char msg[256];
  std::snprintf(msg, sizeof msg,
                "objc_msgSend: %s%s does not respond to %s%s%s",
                k && k->meta ? "+" : "-", k ? k->name.c_str() : "?",
                name ? name : "(unreadable selector)",
                k && !k->external_super.empty() ? ", owed by " : "",
                k && !k->external_super.empty() ? k->external_super.c_str() : "");
  arc_trap(c, msg);
}

void MsgSend(Arm32Ctx* c) {
  const uint32_t receiver = ARC_R(c, 0);
  Send(c, receiver, receiver ? ARC_LD32(receiver) : 0, ARC_R(c, 1));
}

void MsgSendSuper2(Arm32Ctx* c) {
  // r0 points at a struct objc_super { id receiver; Class cls; }. The `2`
  // variant looks up starting from cls's *superclass*, which is what every
  // `[super init]` compiles to.
  const uint32_t sup = ARC_R(c, 0);
  if (!sup) {
    ARC_W(c, 0, 0);
    return;
  }
  const uint32_t receiver = ARC_LD32(sup);
  const uint32_t cls = ARC_LD32(sup + 4);
  const ObjcClass* k = g_objc.ClassAt(cls);
  // The receiver takes r0 back: the callee is an ordinary method and expects
  // the object, not the objc_super it was reached through.
  ARC_W(c, 0, receiver);
  Send(c, receiver, k ? k->superclass : 0, ARC_R(c, 1));
}

void MsgSendStret(Arm32Ctx* c) {
  // A struct-returning send puts the hidden return pointer in r0, so the
  // receiver and selector shift up by one register.
  const uint32_t receiver = ARC_R(c, 1);
  Send(c, receiver, receiver ? ARC_LD32(receiver) : 0, ARC_R(c, 2));
}

}  // namespace

void InstallObjcRuntime(const MachOImage& img) {
  g_image = &img;
  // Lifted code reaches an import by branching to its stub, so the stub
  // address is the name the runtime knows it by. Registering a *host* function
  // pointer rather than deriving one from the guest address matters: a guest
  // address is 32 bits and a host function is not, so "resolved" here can
  // never mean "is a host function".
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    if (im.name == "_objc_msgSend")
      arc_register_ctx_native(im.stub, "objc_msgSend", MsgSend);
    else if (im.name == "_objc_msgSendSuper2")
      arc_register_ctx_native(im.stub, "objc_msgSendSuper2", MsgSendSuper2);
    else if (im.name == "_objc_msgSend_stret")
      arc_register_ctx_native(im.stub, "objc_msgSend_stret", MsgSendStret);
  }
}

}  // namespace arc
