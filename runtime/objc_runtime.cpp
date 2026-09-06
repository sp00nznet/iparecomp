#include "objc_runtime.h"

#include "arc_mem.h"
#include "objc_host.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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
bool g_stret = false;
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
    // A category on a framework class -- NSString, NSArray, UIColor -- has a
    // zero here and a bind entry naming it. The *methods* are still in this
    // binary, so they are lifted code answering messages sent to a class the
    // binary does not define. Attach them to the host class object.
    if (!target || !by_addr_.count(target)) {
      const std::string owner =
          ClassNameOf(img.BoundSymbolAt(c + kCatClass));
      if (owner.empty()) continue;
      for (int pass = 0; pass < 2; ++pass) {
        const uint32_t ml =
            r.U32(c + (pass ? kCatClassMethods : kCatInstanceMethods));
        if (!ml) continue;
        uint32_t entsize = r.U32(ml), count = r.U32(ml + 4);
        if (entsize < kMethodSize || entsize > 64 || count > 4096) {
          entsize = kMethodSize;
          if (count > 4096) count = 0;
        }
        for (uint32_t k = 0; k < count; ++k) {
          const uint32_t e = ml + 8 + k * entsize;
          const std::string sel = r.Str(r.U32(e));
          const uint32_t imp = r.U32(e + 8);
          if (!sel.empty() && imp)
            HostGuestMethod(owner.c_str(), pass != 0, sel.c_str(), imp);
        }
      }
      continue;
    }
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

// The trail is far more use carrying the message than the fact that a message
// happened: twenty lines of "objc_msgSend" say nothing, whereas the selectors
// in order say exactly where the guest got to. The strings are kept alive in a
// deque because the ring holds pointers, not copies.
void NoteMessage(uint32_t cls, const char* selector) {
  static std::deque<std::string> kept;
  const ObjcClass* k = g_objc.ClassAt(cls);
  const char* cn = k ? k->name.c_str() : HostClassName(cls);
  std::string line = k && k->meta ? "+[" : "-[";
  line += cn ? cn : "?";
  line += " ";
  line += selector ? selector : "?";
  line += "]";
  kept.push_back(line);
  if (kept.size() > 256) kept.pop_front();
  arc_trace_note(kept.back().c_str());
}

// `cls` is the class to start the lookup from. Passing zero means "read it out
// of the receiver" -- which has to happen *after* the receiver is checked,
// because reading an isa out of a value that was never an object is exactly
// the fault this is trying to describe. Computing it in the caller's argument
// list is what made the first version of this guard useless.
void Send(Arm32Ctx* c, uint32_t receiver, uint32_t cls, uint32_t sel) {
  // A message to nil is not an error: it evaluates to zero and that is load
  // bearing in real Objective-C, not a corner case.
  if (!receiver) {
    ARC_W(c, 0, 0);
    return;
  }
  // A receiver has to be somewhere the guest could have got a pointer. When it
  // is not, the value was never an object, and dereferencing it to read an isa
  // would fault on whatever it happens to address -- somewhere unrelated, with
  // nothing to say which send was at fault. Refusing here names the selector
  // and leaves the frame ring pointing at the function that passed it.
  if (!arc_guest_plausible(receiver)) {
    char msg[192];
    std::snprintf(msg, sizeof msg,
                  "objc_msgSend: %#x is not an object, and it was sent %s",
                  receiver, SelName(sel) ? SelName(sel) : "(unreadable)");
    arc_trap(c, msg);
    return;
  }
  if (!cls) cls = ARC_LD32(receiver);
  const char* name = SelName(sel);
  NoteMessage(cls, name);
  // The message equivalent of ARC_TRACE_CALLS. A name in the trail says a
  // message was sent; the arguments say whether what it carried made sense,
  // which is the difference between watching a value arrive wrong and
  // inferring where it went wrong. Set to a substring, or "*" for everything.
  {
    static const char* filter;
    static bool checked;
    if (!checked) {
      filter = std::getenv("ARC_TRACE_MSG");
      checked = true;
    }
    if (filter && name && (!*filter || *filter == '*' || strstr(name, filter))) {
      const ObjcClass* k = g_objc.ClassAt(cls);
      const char* cn = k ? k->name.c_str() : HostClassName(cls);
      const uint32_t sp = ARC_SP(c);
      std::printf("[msg] %s[%s %s] r2=%#x r3=%#x sp0=%#x sp1=%#x sp2=%#x\n",
                  k && k->meta ? "+" : "-", cn ? cn : "?", name,
                  ARC_R(c, 2), ARC_R(c, 3),
                  arc_guest_owns(sp, 4) ? ARC_LD32(sp) : 0,
                  arc_guest_owns(sp + 4, 4) ? ARC_LD32(sp + 4) : 0,
                  arc_guest_owns(sp + 8, 4) ? ARC_LD32(sp + 8) : 0);
    }
  }
  const uint32_t imp = g_objc.Lookup(cls, name);
  if (imp) {
    // Registers are already arranged as the guest left them: receiver in r0,
    // selector in r1, arguments after. The implementation is lifted code.
    arc_dispatch(c, imp);
    return;
  }
  // Not on the class itself, so a framework owes it -- but a category in this
  // binary may still answer, and that is lifted code, so it goes first.
  if (const uint32_t cat = LookupHostImp(cls, name)) {
    arc_dispatch(c, cat);
    return;
  }
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
    //
    // The hazard is real and worth a stop rather than a comment: a loop whose
    // exit condition depends on an answer will not terminate if the answer is
    // always nil, and a measuring run that never ends measures nothing. The
    // budget is large enough that no honest launch reaches it.
    static long budget = 2000000;
    if (--budget < 0)
      arc_trap(c, "permissive mode answered two million messages with nil; "
                  "the guest is almost certainly looping on one of them");
    const std::string cn = where ? where : "?";
    const std::string sn = name ? name : "(unreadable selector)";
    if (g_missing_seen.insert(cn + " " + sn).second)
      g_missing.emplace_back(cn, sn);
    ARC_W(c, 0, 0);
    return;
  }
  if (!k) {
    char msg[256];
    // An unknown class is usually a bad pointer rather than a missing method,
    // and the two want telling apart -- so say what was actually in the
    // registers instead of only that the lookup failed.
    std::snprintf(msg, sizeof msg,
                  "objc_msgSend: %s does not respond to %s "
                  "(receiver %#x, isa %#x)",
                  where ? where : "an unknown class",
                  name ? name : "(unreadable selector)", receiver, cls);
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
  g_stret = false;
  Send(c, ARC_R(c, 0), 0, ARC_R(c, 1));
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
  uint32_t super = k ? k->superclass : 0;
  if (k && !super) {
    // The superclass is not in this binary, which is the ordinary case for
    // `[super init]` -- almost every class here inherits NSObject directly.
    // Zero would send the message to nothing, so step across to the host
    // class the bind table named.
    super = HostClassByName(k->external_super.c_str(), k->meta);
  }
  // The receiver takes r0 back: the callee is an ordinary method and expects
  // the object, not the objc_super it was reached through.
  ARC_W(c, 0, receiver);
  Send(c, receiver, super, ARC_R(c, 1));
}

// --- the property helpers --------------------------------------------------
// A synthesized property accessor does not read or write the ivar itself; it
// calls into the runtime, which is where atomicity and retain semantics would
// live. Neither applies here -- nothing is threaded and nothing is reference
// counted -- so each of these is the copy it would have ended up doing.

// objc_copyStruct(dest, src, size, atomic, hasStrong)
void CopyStruct(Arm32Ctx* c) {
  const uint32_t dst = ARC_R(c, 0), src = ARC_R(c, 1), n = ARC_R(c, 2);
  if (dst && src && n && n < (1u << 20))
    memmove(reinterpret_cast<void*>(uintptr_t(dst)),
            reinterpret_cast<const void*>(uintptr_t(src)), n);
}

// objc_getProperty(self, _cmd, offset, atomic)
void GetProperty(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0), offset = ARC_R(c, 2);
  ARC_W(c, 0, self ? ARC_LD32(self + offset) : 0);
}

// objc_setProperty(self, _cmd, offset, value, atomic, shouldCopy)
void SetProperty(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0), offset = ARC_R(c, 2), value = ARC_R(c, 3);
  if (self) ARC_ST32(self + offset, value);
}

// Raised when a collection is mutated while being enumerated. Reaching it is
// a bug in the guest, not here, and it is loud on a device too.
void EnumerationMutation(Arm32Ctx* c) {
  arc_trap(c, "objc_enumerationMutation: a collection changed while being "
               "enumerated");
}

void MsgSendStret(Arm32Ctx* c) {
  // A struct-returning send puts the hidden return pointer in r0, so the
  // receiver and selector shift up by one register.
  g_stret = true;
  Send(c, ARC_R(c, 1), 0, ARC_R(c, 2));
  g_stret = false;
}

}  // namespace

bool SendingStret() { return g_stret; }

void InstallObjcRuntime(const MachOImage& img) {
  g_image = &img;
  // The receiver guard needs to know what the image occupies, and this is
  // where the runtime becomes live -- setting it only in Boot left every
  // address implausible on any path that does not boot, which silently
  // refused all 88 of the dispatch self-check's messages.
  {
    uint32_t lo = 0xFFFFFFFFu, hi = 0;
    for (const auto& seg : img.segments()) {
      if (!seg.vmsize || seg.name == "__PAGEZERO") continue;
      lo = seg.vmaddr < lo ? seg.vmaddr : lo;
      hi = seg.vmaddr + seg.vmsize > hi ? seg.vmaddr + seg.vmsize : hi;
    }
    arc_set_image_range(lo, hi);
  }
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
    else if (im.name == "_objc_copyStruct")
      arc_register_ctx_native(im.stub, "objc_copyStruct", CopyStruct);
    else if (im.name == "_objc_getProperty")
      arc_register_ctx_native(im.stub, "objc_getProperty", GetProperty);
    else if (im.name == "_objc_setProperty")
      arc_register_ctx_native(im.stub, "objc_setProperty", SetProperty);
    else if (im.name == "_objc_enumerationMutation")
      arc_register_ctx_native(im.stub, "objc_enumerationMutation",
                              EnumerationMutation);
  }
}

}  // namespace arc
