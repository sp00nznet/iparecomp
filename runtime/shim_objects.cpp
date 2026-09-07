// The Foundation and UIKit objects the startup path asks for.
//
// None of this is a Foundation. Each one is the smallest thing that answers
// what the game actually sends -- which is known, because a permissive run
// lists it -- and no more. The point is to keep the guest moving so the next
// requirement becomes visible; anything built ahead of that is guesswork.
//
// Where a shortcut is taken it is named. The ones here are: no reference
// counting, no threading, and dictionaries keyed by string content rather than
// by a real hash of an arbitrary object.
#include <cmath>
#include "macho_image.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "arc_mem.h"
#include "arm32_context.h"
#include "objc_host.h"
#include "objc_runtime.h"

namespace arc {

// Defined below, but named here: a shim inside the anonymous namespace needs
// it before the definition is reached.
std::string BundlePath();

namespace {

std::string StringText(uint32_t obj);

// --- boxed values ----------------------------------------------------------
// An NSNumber is an isa and a double. Keeping one representation rather than
// tagging by type means -intValue on something made with +numberWithFloat:
// truncates, which is what the real one does.
struct Boxed {
  double value = 0;
};

std::map<uint32_t, Boxed>& Numbers() {
  static std::map<uint32_t, Boxed> m;
  return m;
}

// Where a shim keeps whatever a guest object needs beyond its isa. Keyed on
// the guest address, so the object itself stays four bytes and the guest can
// hold it in a register like any other.
std::map<uint32_t, std::map<std::string, uint32_t>>& Fields() {
  static std::map<uint32_t, std::map<std::string, uint32_t>> m;
  return m;
}

float F32(uint32_t bits) {
  float f;
  std::memcpy(&f, &bits, 4);
  return f;
}

uint32_t Bits(float f) {
  uint32_t u;
  std::memcpy(&u, &f, 4);
  return u;
}

uint32_t MakeNumber(double v) {
  const uint32_t obj = HostAllocInstance(HostClass("NSNumber", "NSObject"));
  if (obj) Numbers()[obj] = {v};
  return obj;
}

double NumberValue(uint32_t obj) {
  auto it = Numbers().find(obj);
  return it == Numbers().end() ? 0.0 : it->second.value;
}

void NumberWithInteger(Arm32Ctx* c) {
  ARC_W(c, 0, MakeNumber(double(int32_t(ARC_R(c, 2)))));
}
void NumberWithBool(Arm32Ctx* c) {
  ARC_W(c, 0, MakeNumber(ARC_R(c, 2) ? 1.0 : 0.0));
}
void NumberWithFloat(Arm32Ctx* c) {
  ARC_W(c, 0, MakeNumber(double(F32(ARC_R(c, 2)))));
}
void IntValue(Arm32Ctx* c) {
  ARC_W(c, 0, uint32_t(int32_t(NumberValue(ARC_R(c, 0)))));
}
void FloatValue(Arm32Ctx* c) {
  ARC_W(c, 0, Bits(float(NumberValue(ARC_R(c, 0)))));
}
void BoolValue(Arm32Ctx* c) {
  ARC_W(c, 0, NumberValue(ARC_R(c, 0)) != 0.0 ? 1 : 0);
}

// --- strings and keys ------------------------------------------------------
// A key is either a CFConstantString the compiler emitted or something a shim
// made. Both are read as text, and a dictionary keyed on the text is right
// where pointer identity would not be: the same literal can appear more than
// once in a binary.
constexpr uint32_t kCFStringChars = 8;

std::string KeyText(uint32_t obj) {
  if (!obj) return std::string();
  const std::string s = StringText(obj);
  if (!s.empty()) return s;
  char buf[24];
  // A boxed pointer keys on what it boxes, not on the box. Two NSValues made
  // from the same pointer are equal to a real NSDictionary and have to be
  // equal here: Canabalt keys its per-class sprite setup by
  // `[NSValue valueWithPointer:[self class]]`, and boxing the same class
  // twice was giving two different keys, so every sprite after the first
  // "was not initialized, making a best guess".
  auto it = Fields().find(obj);
  if (it != Fields().end()) {
    auto p = it->second.find("pointer");
    if (p != it->second.end()) {
      std::snprintf(buf, sizeof buf, "@%08x", p->second);
      return buf;
    }
  }
  // Not a string and not a box: key on identity, which is right for an object
  // used as a token rather than as text.
  std::snprintf(buf, sizeof buf, "#%08x", obj);
  return buf;
}

uint32_t Singleton(const char* name);

// --- strings ---------------------------------------------------------------
// A host string is given the same shape as a CFConstantString -- isa, flags,
// bytes, length -- so that one reader handles both the literals the compiler
// emitted and the strings a shim made. The characters live in guest memory
// too, because the guest is entitled to take `-UTF8String` and pass it to
// anything expecting a char*.
std::map<uint32_t, std::string>& Strings() {
  static std::map<uint32_t, std::string> m;
  return m;
}

uint32_t MakeString(const std::string& text) {
  const uint32_t obj = HostAllocInstance(HostClass("NSString", "NSObject"));
  if (!obj) return 0;
  const uint32_t chars = arc_guest_strdup(text.c_str());
  ARC_ST32(obj + 8, chars);
  ARC_ST32(obj + 12, uint32_t(text.size()));
  Strings()[obj] = text;
  return obj;
}

std::string StringText(uint32_t obj) {
  if (!obj) return std::string();
  auto it = Strings().find(obj);
  if (it != Strings().end()) return it->second;
  const uint32_t p = ARC_LD32(obj + kCFStringChars);
  if (!p) return std::string();
  return reinterpret_cast<const char*>(uintptr_t(p));
}

// The arguments after self and _cmd: r2 and r3, then the stack. Every variadic
// shim needs the same walk, so it is done once.
std::vector<uint32_t> VarArgs(Arm32Ctx* c, int first) {
  std::vector<uint32_t> out;
  for (int r = first; r <= 3; ++r) out.push_back(ARC_R(c, uint32_t(r)));
  const uint32_t sp = ARC_SP(c);
  for (int i = 0; i < 24 && arc_guest_owns(sp + i * 4, 4); ++i)
    out.push_back(ARC_LD32(sp + i * 4));
  return out;
}

// ponytail: enough of the format language to carry the strings this game
// builds -- %@, %d/%i/%u, %f/%g with a width, %s, %c, %%. A double takes two
// words under the soft-float ABI and is eight-aligned, which is the one part
// that is easy to get quietly wrong. Anything unrecognised is copied through
// verbatim rather than guessed at, so it shows up in the output instead of
// being silently dropped.
std::string FormatWith(const std::string& fmt, const std::vector<uint32_t>& a) {
  std::string out;
  size_t arg = 0;
  for (size_t i = 0; i < fmt.size(); ++i) {
    if (fmt[i] != '%') {
      out += fmt[i];
      continue;
    }
    size_t j = i + 1;
    while (j < fmt.size() && !std::strchr("@diufgGsc%xX", fmt[j])) ++j;
    if (j >= fmt.size()) {
      out += fmt.substr(i);
      break;
    }
    const char conv = fmt[j];
    const std::string spec = fmt.substr(i, j - i + 1);
    char buf[256];
    if (conv == '%') {
      out += '%';
    } else if (conv == '@') {
      out += arg < a.size() ? StringText(a[arg++]) : std::string("(null)");
    } else if (conv == 's') {
      const uint32_t p = arg < a.size() ? a[arg++] : 0;
      out += p ? reinterpret_cast<const char*>(uintptr_t(p)) : "(null)";
    } else if (conv == 'f' || conv == 'g' || conv == 'G') {
      // Eight-aligned, and two words wide.
      if (arg % 2) ++arg;
      uint64_t bits = 0;
      if (arg + 1 < a.size()) bits = uint64_t(a[arg]) | (uint64_t(a[arg + 1]) << 32);
      arg += 2;
      double d;
      std::memcpy(&d, &bits, 8);
      std::snprintf(buf, sizeof buf, spec.c_str(), d);
      out += buf;
    } else {
      const uint32_t v = arg < a.size() ? a[arg++] : 0;
      std::snprintf(buf, sizeof buf, spec.c_str(), v);
      out += buf;
    }
    i = j;
  }
  return out;
}

void StringWithString(Arm32Ctx* c) {
  ARC_W(c, 0, MakeString(StringText(ARC_R(c, 2))));
}

void StringWithUTF8String(Arm32Ctx* c) {
  const uint32_t p = ARC_R(c, 2);
  ARC_W(c, 0, MakeString(p ? reinterpret_cast<const char*>(uintptr_t(p)) : ""));
}

void StringWithFormat(Arm32Ctx* c) {
  const std::string fmt = StringText(ARC_R(c, 2));
  ARC_W(c, 0, MakeString(FormatWith(fmt, VarArgs(c, 3))));
}

void UTF8String(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  auto it = Strings().find(self);
  if (it != Strings().end()) {
    ARC_W(c, 0, ARC_LD32(self + 8));
    return;
  }
  ARC_W(c, 0, ARC_LD32(self + kCFStringChars));
}

void StringLength(Arm32Ctx* c) {
  ARC_W(c, 0, uint32_t(StringText(ARC_R(c, 0)).size()));
}

void IsEqualToString(Arm32Ctx* c) {
  ARC_W(c, 0, StringText(ARC_R(c, 0)) == StringText(ARC_R(c, 2)) ? 1 : 0);
}

// A localized string with no table falls back to the key, which is what the
// real one does when the lookup misses.
void LocalizedStringForKey(Arm32Ctx* c) {
  ARC_W(c, 0, MakeString(StringText(ARC_R(c, 2))));
}

// Reading a URL is how this game reaches Twitter. There is no network here and
// there does not need to be: nil is what an offline device returns, and the
// game already handles it.
void NilMethod(Arm32Ctx* c) { ARC_W(c, 0, 0); }

// Parsing a number out of a string. Answering these with nil means every
// value a game reads from a config file or a bundle key is zero, and a game
// that checks its own configuration then reports an error about it -- which is
// how Angry Birds ends up building an exception message at startup.
void StringFloatValue(Arm32Ctx* c) {
  const std::string t = StringText(ARC_R(c, 0));
  float f = 0.0f;
  try { f = std::stof(t); } catch (...) { f = 0.0f; }
  uint32_t bits;
  std::memcpy(&bits, &f, 4);
  ARC_W(c, 0, bits);
}

void StringIntValue(Arm32Ctx* c) {
  const std::string t = StringText(ARC_R(c, 0));
  long v = 0;
  try { v = std::stol(t); } catch (...) { v = 0; }
  ARC_W(c, 0, uint32_t(int32_t(v)));
}

void StringDoubleValue(Arm32Ctx* c) {
  const std::string t = StringText(ARC_R(c, 0));
  double d = 0.0;
  try { d = std::stod(t); } catch (...) { d = 0.0; }
  uint64_t bits;
  std::memcpy(&bits, &d, 8);
  ARC_W(c, 0, uint32_t(bits));
  ARC_W(c, 1, uint32_t(bits >> 32));
}

void StringBoolValue(Arm32Ctx* c) {
  const std::string t = StringText(ARC_R(c, 0));
  const bool yes = !t.empty() && (t[0] == 'Y' || t[0] == 'y' || t[0] == 'T' ||
                                  t[0] == 't' || (t[0] >= '1' && t[0] <= '9'));
  ARC_W(c, 0, yes ? 1u : 0u);
}

void URLWithString(Arm32Ctx* c) {
  const uint32_t obj = HostAllocInstance(HostClass("NSURL", "NSObject"));
  if (obj) Strings()[obj] = StringText(ARC_R(c, 2));
  ARC_W(c, 0, obj);
}

void CurrentDevice(Arm32Ctx* c) {
  ARC_W(c, 0, Singleton("UIDevice"));
}

// --- dictionaries ----------------------------------------------------------
std::map<uint32_t, std::map<std::string, uint32_t>>& Dicts() {
  static std::map<uint32_t, std::map<std::string, uint32_t>> m;
  return m;
}

uint32_t MakeDict(const char* cls) {
  const uint32_t obj = HostAllocInstance(HostClass(cls, "NSObject"));
  if (obj) Dicts()[obj];
  return obj;
}

// +dictionaryWithObjectsAndKeys: is variadic and nil-terminated. Under AAPCS
// the first two arguments after self and _cmd are in r2 and r3 and the rest
// are on the stack, which is why this reads both.
void DictionaryWithObjectsAndKeys(Arm32Ctx* c) {
  const uint32_t obj = MakeDict("NSDictionary");
  if (!obj) return;
  auto& d = Dicts()[obj];
  std::vector<uint32_t> args{ARC_R(c, 2), ARC_R(c, 3)};
  const uint32_t sp = ARC_SP(c);
  for (int i = 0; i < 16 && arc_guest_owns(sp + i * 4, 4); ++i)
    args.push_back(ARC_LD32(sp + i * 4));
  for (size_t i = 0; i + 1 < args.size(); i += 2) {
    if (!args[i]) break;  // the nil terminator
    d[KeyText(args[i + 1])] = args[i];
  }
  ARC_W(c, 0, obj);
}

void ObjectForKey(Arm32Ctx* c) {
  auto it = Dicts().find(ARC_R(c, 0));
  if (it == Dicts().end()) {
    ARC_W(c, 0, 0);
    return;
  }
  auto v = it->second.find(KeyText(ARC_R(c, 2)));
  ARC_W(c, 0, v == it->second.end() ? 0 : v->second);
}

void SetObjectForKey(Arm32Ctx* c) {
  Dicts()[ARC_R(c, 0)][KeyText(ARC_R(c, 3))] = ARC_R(c, 2);
  ARC_W(c, 0, 0);
}

// Every host class was being created with NSObject as its superclass, which
// makes the hierarchy decoration rather than structure. A method lookup that
// misses walks the superclass chain, so a flat hierarchy means NSMutableArray
// answers nothing NSArray implements -- count, objectAtIndex:, lastObject,
// the fast enumeration -- and the guest is told the class does not respond to
// `count`. These are the pairs where the real hierarchy carries methods; the
// default stays NSObject.
const char* HostSuperOf(const char* cls) {
  static const struct {
    const char* cls;
    const char* super;
  } kSupers[] = {
      {"NSMutableArray", "NSArray"},
      {"NSMutableSet", "NSSet"},
      {"NSMutableDictionary", "NSDictionary"},
      {"NSMutableString", "NSString"},
      {"NSMutableData", "NSData"},
  };
  for (const auto& k : kSupers)
    if (std::strcmp(cls, k.cls) == 0) return k.super;
  return "NSObject";
}

// --- arrays ----------------------------------------------------------------
// Real ones, because the game keeps score lists and sprite groups in them and
// reads them back. An array that silently stays empty is a menu with no
// buttons in it, which looks like a rendering problem rather than a missing
// collection.
std::map<uint32_t, std::vector<uint32_t>>& Arrays() {
  static std::map<uint32_t, std::vector<uint32_t>> m;
  return m;
}

uint32_t MakeArray(const char* cls) {
  const uint32_t obj = HostAllocInstance(HostClass(cls, HostSuperOf(cls)));
  if (obj) Arrays()[obj];
  return obj;
}

void ArrayNew(Arm32Ctx* c) { ARC_W(c, 0, MakeArray("NSMutableArray")); }

void ArrayWithObject(Arm32Ctx* c) {
  const uint32_t a = MakeArray("NSMutableArray");
  if (a && ARC_R(c, 2)) Arrays()[a].push_back(ARC_R(c, 2));
  ARC_W(c, 0, a);
}

// +arrayWithObjects: is nil-terminated and variadic: r2 and r3, then stack.
void ArrayWithObjects(Arm32Ctx* c) {
  const uint32_t a = MakeArray("NSMutableArray");
  if (!a) {
    ARC_W(c, 0, 0);
    return;
  }
  for (uint32_t v : VarArgs(c, 2)) {
    if (!v) break;
    Arrays()[a].push_back(v);
  }
  ARC_W(c, 0, a);
}

// The copy-from-an-array family. `arrayWithArray:` and `addObjectsFromArray:`
// were both wired to ArrayWithObject, which stores the *source array* as a
// single element -- a one-element array whose element is an array, which reads
// back as a count of 1 and an objectAtIndex: that returns something of the
// wrong class. Same argument as the collections themselves: the failure looks
// like a rendering bug rather than a missing method.
void Extend(uint32_t dst, uint32_t src) {
  auto it = Arrays().find(src);
  if (it == Arrays().end()) return;
  auto& out = Arrays()[dst];
  // A copy of the source, not a reference to it, and by value because `out`
  // and `it->second` are the same vector when a guest copies an array onto
  // itself.
  const std::vector<uint32_t> from = it->second;
  out.insert(out.end(), from.begin(), from.end());
}

void ArrayWithArray(Arm32Ctx* c) {
  const uint32_t a = MakeArray("NSMutableArray");
  if (a) Extend(a, ARC_R(c, 2));
  ARC_W(c, 0, a);
}

// -initWithArray: arrives on an object `alloc` already produced, so the
// receiver is returned rather than a new one.
void ArrayInitWithArray(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  if (self) {
    Arrays()[self].clear();
    Extend(self, ARC_R(c, 2));
  }
  ARC_W(c, 0, self);
}

void ArrayAddObjectsFromArray(Arm32Ctx* c) {
  Extend(ARC_R(c, 0), ARC_R(c, 2));
  ARC_W(c, 0, 0);
}

// A set, for the shims' own use. UIKit hands touches over as an NSSet and the
// guest asks it for `anyObject` or walks it with an enumerator, so the set is
// an array with three more methods rather than a second collection.
void ArrayAnyObject(Arm32Ctx* c) {
  auto it = Arrays().find(ARC_R(c, 0));
  ARC_W(c, 0, it == Arrays().end() || it->second.empty() ? 0 : it->second[0]);
}

void ArrayObjectEnumerator(Arm32Ctx* c) {
  const uint32_t e = HostAllocInstance(HostClass("NSEnumerator", "NSObject"));
  if (e) {
    Fields()[e]["array"] = ARC_R(c, 0);
    Fields()[e]["next"] = 0;
  }
  ARC_W(c, 0, e);
}

void EnumeratorNextObject(Arm32Ctx* c) {
  auto e = Fields().find(ARC_R(c, 0));
  if (e == Fields().end()) {
    ARC_W(c, 0, 0);
    return;
  }
  auto it = Arrays().find(e->second["array"]);
  const uint32_t i = e->second["next"];
  if (it == Arrays().end() || i >= it->second.size()) {
    ARC_W(c, 0, 0);
    return;
  }
  e->second["next"] = i + 1;
  ARC_W(c, 0, it->second[i]);
}

// NSSet, backed by the same vector. The only thing a set owes that an array
// does not is that adding a member twice leaves one, so that is the only
// method written out; everything else is the array's, pointed at from the set
// rows of the table. Giving NSSet NSArray as a superclass would have been
// shorter and would also have made `isKindOfClass:[NSArray class]` true,
// which is a lie the guest is entitled to act on.
bool Holds(const std::vector<uint32_t>& v, uint32_t x) {
  for (uint32_t e : v)
    if (e == x) return true;
  return false;
}

uint32_t MakeSet(const char* cls, uint32_t from) {
  const uint32_t a = MakeArray(cls);
  if (!a) return 0;
  auto& out = Arrays()[a];
  out.clear();
  auto it = Arrays().find(from);
  if (it != Arrays().end()) {
    const std::vector<uint32_t> src = it->second;
    for (uint32_t e : src)
      if (!Holds(out, e)) out.push_back(e);
  } else if (from) {
    out.push_back(from);
  }
  return a;
}

void SetNew(Arm32Ctx* c) { ARC_W(c, 0, MakeSet("NSMutableSet", 0)); }
void SetWithCollection(Arm32Ctx* c) {
  ARC_W(c, 0, MakeSet("NSMutableSet", ARC_R(c, 2)));
}
void SetInitWithCollection(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  if (self) {
    auto& out = Arrays()[self];
    out.clear();
    auto it = Arrays().find(ARC_R(c, 2));
    if (it != Arrays().end()) {
      const std::vector<uint32_t> src = it->second;
      for (uint32_t e : src)
        if (!Holds(out, e)) out.push_back(e);
    }
  }
  ARC_W(c, 0, self);
}

void SetAddObject(Arm32Ctx* c) {
  const uint32_t v = ARC_R(c, 2);
  auto& out = Arrays()[ARC_R(c, 0)];
  if (v && !Holds(out, v)) out.push_back(v);
  ARC_W(c, 0, 0);
}

void SetMinus(Arm32Ctx* c) {
  auto other = Arrays().find(ARC_R(c, 2));
  auto self = Arrays().find(ARC_R(c, 0));
  if (other != Arrays().end() && self != Arrays().end()) {
    const std::vector<uint32_t> drop = other->second;
    std::vector<uint32_t> kept;
    for (uint32_t e : self->second)
      if (!Holds(drop, e)) kept.push_back(e);
    self->second.swap(kept);
  }
  ARC_W(c, 0, 0);
}

void SetUnion(Arm32Ctx* c) {
  auto it = Arrays().find(ARC_R(c, 2));
  if (it != Arrays().end()) {
    auto& out = Arrays()[ARC_R(c, 0)];
    const std::vector<uint32_t> src = it->second;
    for (uint32_t e : src)
      if (!Holds(out, e)) out.push_back(e);
  }
  ARC_W(c, 0, 0);
}

void ArrayCount(Arm32Ctx* c) {
  auto it = Arrays().find(ARC_R(c, 0));
  ARC_W(c, 0, it == Arrays().end() ? 0 : uint32_t(it->second.size()));
}

void ArrayObjectAtIndex(Arm32Ctx* c) {
  auto it = Arrays().find(ARC_R(c, 0));
  const uint32_t i = ARC_R(c, 2);
  ARC_W(c, 0, it != Arrays().end() && i < it->second.size() ? it->second[i] : 0);
}

void ArrayLastObject(Arm32Ctx* c) {
  auto it = Arrays().find(ARC_R(c, 0));
  ARC_W(c, 0, it == Arrays().end() || it->second.empty() ? 0
                                                         : it->second.back());
}

void ArrayAddObject(Arm32Ctx* c) {
  if (ARC_R(c, 2)) Arrays()[ARC_R(c, 0)].push_back(ARC_R(c, 2));
  ARC_W(c, 0, 0);
}

void ArrayRemoveObject(Arm32Ctx* c) {
  auto& v = Arrays()[ARC_R(c, 0)];
  const uint32_t want = ARC_R(c, 2);
  for (size_t i = 0; i < v.size(); ++i)
    if (v[i] == want) {
      v.erase(v.begin() + long(i));
      break;
    }
  ARC_W(c, 0, 0);
}

void ArrayRemoveAll(Arm32Ctx* c) {
  Arrays()[ARC_R(c, 0)].clear();
  ARC_W(c, 0, 0);
}

// -countByEnumeratingWithState:objects:count: is what `for (x in array)`
// compiles to. The state block is:
//
//   unsigned long state; id* itemsPtr; unsigned long* mutationsPtr;
//   unsigned long extra[5];
//
// The caller reads the items through `itemsPtr`, so they have to be somewhere
// the guest can point at -- the elements live in a host vector here, so a
// guest buffer is materialised for the enumeration to walk.
//
// `mutationsPtr` is dereferenced before and after each batch and compared: if
// the value changes, the runtime raises. It gets a word that never does.
void CountByEnumerating(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  const uint32_t state = ARC_R(c, 2);
  auto it = Arrays().find(self);
  if (it == Arrays().end() || !state) {
    ARC_W(c, 0, 0);
    return;
  }
  // Everything is returned in one batch, so a second call ends the loop.
  if (ARC_LD32(state + 0)) {
    ARC_W(c, 0, 0);
    return;
  }
  const uint32_t n = uint32_t(it->second.size());
  const uint32_t buf = arc_guest_alloc(n * 4 + 4, 4);
  if (!buf) {
    ARC_W(c, 0, 0);
    return;
  }
  for (uint32_t i = 0; i < n; ++i) ARC_ST32(buf + i * 4, it->second[i]);
  ARC_ST32(buf + n * 4, 0);   // the mutation counter, which never moves
  ARC_ST32(state + 0, 1);     // state: this batch has been handed out
  ARC_ST32(state + 4, buf);   // itemsPtr
  ARC_ST32(state + 8, buf + n * 4);  // mutationsPtr
  if (std::getenv("ARC_TRACE_MSG")) {
    std::printf("[enum] state=%#x items=%#x n=%u :", state, buf, n);
    for (uint32_t i = 0; i < n && i < 12; ++i)
      std::printf(" %08x", ARC_LD32(buf + i * 4));
    std::printf("\n");
  }
  ARC_W(c, 0, n);
}

void ArrayContains(Arm32Ctx* c) {
  auto it = Arrays().find(ARC_R(c, 0));
  const uint32_t want = ARC_R(c, 2);
  bool found = false;
  if (it != Arrays().end())
    for (uint32_t v : it->second) found = found || v == want;
  ARC_W(c, 0, found ? 1 : 0);
}

// --- singletons ------------------------------------------------------------
uint32_t Singleton(const char* name) {
  static std::map<std::string, uint32_t> made;
  auto it = made.find(name);
  if (it != made.end()) return it->second;
  const uint32_t obj = MakeDict(name);
  made[name] = obj;
  return obj;
}

void StandardUserDefaults(Arm32Ctx* c) {
  ARC_W(c, 0, Singleton("NSUserDefaults"));
}
void MainBundle(Arm32Ctx* c) { ARC_W(c, 0, Singleton("NSBundle")); }

// Its own object. Handing back the user-defaults singleton instead was a
// shortcut that cost more than it saved: identity is what these are for, and
// two singletons sharing one address means a message meant for either can
// arrive at the other.
void DefaultCenter(Arm32Ctx* c) {
  ARC_W(c, 0, Singleton("NSNotificationCenter"));
}
void Synchronize(Arm32Ctx* c) { ARC_W(c, 0, 1); }

// A default that was never written reads as zero, which for -integerForKey:
// and -floatForKey: is the documented answer rather than a stand-in.
void IntegerForKey(Arm32Ctx* c) {
  auto& d = Dicts()[ARC_R(c, 0)];
  auto v = d.find(KeyText(ARC_R(c, 2)));
  ARC_W(c, 0, v == d.end() ? 0 : uint32_t(int32_t(NumberValue(v->second))));
}

void FloatForKey(Arm32Ctx* c) {
  auto& d = Dicts()[ARC_R(c, 0)];
  auto v = d.find(KeyText(ARC_R(c, 2)));
  ARC_W(c, 0, v == d.end() ? 0 : Bits(float(NumberValue(v->second))));
}

// --- UIColor ---------------------------------------------------------------
// A colour is now asked what it is made of. `-[FlxTexture initWithColor:]`
// reads `CGColorGetNumberOfComponents` and refuses anything that is not four,
// with "invalid component count in color" -- so an opaque token is no longer
// enough, and a UIColor doubles as its own CGColorRef because nothing here
// distinguishes them.
void SetColorComponents(uint32_t obj, float r, float g, float b, float a) {
  if (!obj) return;
  auto& f = Fields()[obj];
  f["r"] = Bits(r);
  f["g"] = Bits(g);
  f["b"] = Bits(b);
  f["a"] = Bits(a);
  f["rgba"] = 1;
}

void ColorNumberOfComponents(Arm32Ctx* c) {
  auto it = Fields().find(ARC_R(c, 0));
  ARC_W(c, 0, it != Fields().end() && it->second.count("rgba") ? 4u : 0u);
}

// CGColorGetComponents returns a pointer to the floats, so they have to live
// somewhere the guest can read. One buffer, refilled per call: the caller
// reads it immediately and never holds it.
void ColorComponents(Arm32Ctx* c) {
  auto it = Fields().find(ARC_R(c, 0));
  if (it == Fields().end() || !it->second.count("rgba")) {
    ARC_W(c, 0, 0);
    return;
  }
  static uint32_t buf = 0;
  if (!buf) buf = arc_guest_alloc(16, 4);
  if (!buf) {
    ARC_W(c, 0, 0);
    return;
  }
  const char* keys[4] = {"r", "g", "b", "a"};
  for (int i = 0; i < 4; ++i)
    ARC_ST32(buf + uint32_t(i) * 4, it->second[keys[i]]);
  ARC_W(c, 0, buf);
}

void ColorWithRGBA(Arm32Ctx* c) {
  // Four floats under the soft-float ABI: r2, r3, then the stack.
  const uint32_t obj = HostAllocInstance(HostClass("UIColor", "NSObject"));
  if (!obj) return;
  auto& f = Fields()[obj];
  f["r"] = ARC_R(c, 2);
  f["g"] = ARC_R(c, 3);
  const uint32_t sp = ARC_SP(c);
  f["b"] = arc_guest_owns(sp, 4) ? ARC_LD32(sp) : 0;
  f["a"] = arc_guest_owns(sp + 4, 4) ? ARC_LD32(sp + 4) : Bits(1.0f);
  f["rgba"] = 1;
  ARC_W(c, 0, obj);
}

// --- operations ------------------------------------------------------------
// An operation is queued, not run. That is not a shortcut -- it is the
// difference between matching the real semantics and not.
//
// Running it inline was the first attempt and it was wrong in a way worth
// recording: NSOperationQueue is asynchronous, so Canabalt's `backgroundTask`
// -- keychain, Twitter, the network -- ran *before* the launch path continued,
// and a peripheral path ended up blocking the critical one. Queueing it puts
// the order back: the main thread carries on, and the queue is drained when
// there is a run loop to drain it from.
void InitWithTargetSelectorObject(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  auto& f = Fields()[self];
  f["target"] = ARC_R(c, 2);
  f["selector"] = ARC_R(c, 3);
  const uint32_t sp = ARC_SP(c);
  f["object"] = arc_guest_owns(sp, 4) ? ARC_LD32(sp) : 0;
  ARC_W(c, 0, self);
}

std::vector<uint32_t>& Queued() {
  static std::vector<uint32_t> q;
  return q;
}

void AddOperation(Arm32Ctx* c) {
  Queued().push_back(ARC_R(c, 2));
  ARC_W(c, 0, 0);
}

// -performSelector:withObject:afterDelay: -- a message posted to the run loop,
// which is exactly what it says and exactly what it must not be turned into.
// Canabalt's buttons use it for their action, and running it inline would put
// the new state's construction inside the old state's render. Same lesson as
// the operation queue and the animation completions: an asynchronous thing
// run synchronously arrives before the thing it depends on.
struct Perform {
  uint32_t target = 0, sel = 0, object = 0;
  std::chrono::steady_clock::time_point due;
};

std::vector<Perform>& Performs() {
  static std::vector<Perform> v;
  return v;
}

void PerformAfterDelay(Arm32Ctx* c) {
  Perform p;
  p.target = ARC_R(c, 0);
  p.sel = ARC_R(c, 2);
  p.object = ARC_R(c, 3);
  const uint32_t bits = ARC_LD32(ARC_SP(c));
  float delay;
  std::memcpy(&delay, &bits, 4);
  if (!(delay > 0) || delay > 60) delay = 0;
  p.due = std::chrono::steady_clock::now() +
          std::chrono::duration_cast<std::chrono::steady_clock::duration>(
              std::chrono::duration<double>(delay));
  if (p.target && p.sel) Performs().push_back(p);
  ARC_W(c, 0, 0);
}

void Nop(Arm32Ctx* c) { ARC_W(c, 0, 0); }

// -[AVAudioPlayer initWithContentsOfURL:error:] fails, for the same reason
// the AudioFile shims report an error rather than success with nothing in it:
// a player that claims to have loaded a file it has not is asked to play it,
// and the failure surfaces somewhere unrelated. Failing here sends the guest
// down the path it already has for a device that will not give it sound.
//
// The out-parameter is an `NSError**` and gets nil written through it, which
// is legal -- a caller that logs it prints "(null)" -- and messaging nil is
// how the rest of that path stays quiet.
//
// ponytail: no player object at all. When something needs sound, this becomes
// a real instance and `play`/`stop`/`setVolume:` become SDL calls.
void AudioPlayerInitFailed(Arm32Ctx* c) {
  if (const uint32_t err = ARC_R(c, 3)) ARC_ST32(err, 0);
  ARC_W(c, 0, 0);
}
void SelfMethod(Arm32Ctx*) {}

// -performSelector: and -performSelector:withObject: are an ordinary send with
// the selector arriving as a value rather than in the instruction stream, so
// this rearranges the registers into what a method expects and dispatches.
void PerformSelector(Arm32Ctx* c) {
  const uint32_t self = ARC_R(c, 0);
  const uint32_t sel = ARC_R(c, 2);
  const uint32_t arg = ARC_R(c, 3);
  if (!self || !sel) {
    ARC_W(c, 0, 0);
    return;
  }
  const uint32_t cls = ARC_LD32(self);
  const char* name = reinterpret_cast<const char*>(uintptr_t(sel));
  ARC_W(c, 0, self);
  ARC_W(c, 1, sel);
  ARC_W(c, 2, arg);
  if (const uint32_t imp = Objc().Lookup(cls, name)) {
    arc_dispatch(c, imp);
    return;
  }
  if (const ArcCtxFn fn = LookupHostMethod(cls, name)) {
    fn(c);
    return;
  }
  ARC_W(c, 0, 0);
}

// --- what text layout asks a string for ------------------------------------

// -getCharacters: copies UTF-16 code units into a buffer the caller sized from
// -length. The strings here are ASCII, so this is a widening copy; anything
// outside it would need real UTF-8 decoding and would show up as the wrong
// glyph rather than a crash.
void GetCharacters(Arm32Ctx* c) {
  const std::string text = StringText(ARC_R(c, 0));
  const uint32_t out = ARC_R(c, 2);
  if (!out) return;
  for (size_t i = 0; i < text.size(); ++i)
    ARC_ST16(out + uint32_t(i) * 2, uint16_t(uint8_t(text[i])));
  ARC_W(c, 0, 0);
}

void CharacterAtIndex(Arm32Ctx* c) {
  const std::string text = StringText(ARC_R(c, 0));
  const uint32_t i = ARC_R(c, 2);
  ARC_W(c, 0, i < text.size() ? uint32_t(uint8_t(text[i])) : 0);
}

// NSNotFound. A search that finds nothing has to say so with this exact value:
// zero means "found at the start", and a word-wrapping loop handed that
// forever does not terminate. This is what the permissive budget caught.
constexpr uint32_t kNotFound = 0x7FFFFFFF;

// -rangeOfCharacterFromSet:options:range: returns an NSRange, and this arrives
// through objc_msgSend_stret rather than the ordinary one.
//
// That is not a detail. Under stret the hidden return pointer takes r0 and
// everything shifts up: the receiver is r1, the selector r2, and the first
// argument r3. Reading it as an ordinary send takes the *string* for a return
// buffer and the selector for the string -- which is what had the word-wrap
// loop searching a nonexistent string forever and never advancing.
//
// An NSRange is only eight bytes, so it looks small enough to come back in a
// register pair; the Objective-C ABI sends it through stret anyway. Where an
// aggregate goes is the ABI's decision, not a size calculation.
void RangeOfCharacterFromSet(Arm32Ctx* c) {
  const uint32_t out = ARC_R(c, 0);
  const std::string text = StringText(ARC_R(c, 1));
  // set is r3; options and the range to search in follow on the stack.
  const uint32_t sp = ARC_SP(c);
  uint32_t from = 0, len = uint32_t(text.size());
  if (arc_guest_owns(sp + 4, 8)) {
    from = ARC_LD32(sp + 4);
    len = ARC_LD32(sp + 8);
  }
  if (from > text.size()) from = uint32_t(text.size());
  if (from + len > text.size()) len = uint32_t(text.size()) - from;

  // The only set anything here asks for is the newline set, so this looks for
  // a newline rather than modelling NSCharacterSet.
  const size_t at = text.find_first_of("\n\r", from);
  const bool found = at != std::string::npos && at < size_t(from) + len;
  if (!out) return;
  ARC_ST32(out + 0, found ? uint32_t(at) : kNotFound);
  ARC_ST32(out + 4, found ? 1u : 0u);
}

void NewlineCharacterSet(Arm32Ctx* c) {
  ARC_W(c, 0, HostAllocInstance(HostClass("NSCharacterSet", "NSObject")));
}

// The bundle's resources are wherever the host was started from. A real path
// beats a plausible one: anything that opens it succeeds or fails honestly
// instead of failing later for a reason that looks unrelated.
void ResourcePath(Arm32Ctx* c);

// -[NSBundle pathForResource:ofType:] -- nil until now, and nil is the wrong
// answer when the file is right there. It is how a title finds everything it
// did not compile in: Canabalt's `+[NokiaFont initialize]` asks for Nokia.ttf
// this way, and got nil, so the CGFont was never made, so every glyph was
// skipped, so every texture uploaded was blank.
//
// The answer is only given when the file actually exists, because a path that
// does not open fails later somewhere that looks unrelated.
void PathForResource(Arm32Ctx* c);

void ValueWithPointer(Arm32Ctx* c) {
  const uint32_t obj = HostAllocInstance(HostClass("NSValue", "NSObject"));
  if (obj) Fields()[obj]["pointer"] = ARC_R(c, 2);
  ARC_W(c, 0, obj);
}

void PointerValue(Arm32Ctx* c) {
  auto it = Fields().find(ARC_R(c, 0));
  ARC_W(c, 0, it == Fields().end() ? 0 : it->second["pointer"]);
}

// --- plain C imports that want the same machinery --------------------------

// NSLog is the game talking. It costs nothing to answer and it is the only
// channel the guest has for saying what it thinks is happening, which during
// bring-up is worth more than most of what a shim could return.
void NSLogShim(Arm32Ctx* c) {
  const std::string fmt = StringText(ARC_R(c, 0));
  std::vector<uint32_t> args;
  for (uint32_t r = 1; r <= 3; ++r) args.push_back(ARC_R(c, r));
  const uint32_t sp = ARC_SP(c);
  for (int i = 0; i < 24 && arc_guest_owns(sp + i * 4, 4); ++i)
    args.push_back(ARC_LD32(sp + i * 4));
  std::printf("[guest] %s\n", FormatWith(fmt, args).c_str());
  ARC_W(c, 0, 0);
}

// A directory the guest may write a high score into. It gets a real path so
// that anything opening it succeeds, rather than a plausible-looking string
// that fails at the first use.
void SearchPathForDirectories(Arm32Ctx* c) {
  const uint32_t arr = MakeDict("NSArray");
  Dicts()[arr]["0"] = MakeString(".");
  ARC_W(c, 0, arr);
}

void StringFromClass(Arm32Ctx* c) {
  const uint32_t cls = ARC_R(c, 0);
  const ObjcClass* k = Objc().ClassAt(cls);
  const char* name = k ? k->name.c_str() : HostClassName(cls);
  ARC_W(c, 0, MakeString(name ? name : ""));
}

void ClassFromString(Arm32Ctx* c) {
  const std::string want = StringText(ARC_R(c, 0));
  for (const auto& k : Objc().classes())
    if (!k.meta && k.name == want) {
      ARC_W(c, 0, k.addr);
      return;
    }
  ARC_W(c, 0, HostClassByName(want.c_str(), false));
}

// Seconds since the reference date. Only the differences matter -- this is
// what the frame timer is built on -- so the epoch is arbitrary and the
// monotonicity is not.
void AbsoluteTimeGetCurrent(Arm32Ctx* c) {
  static const auto start = std::chrono::steady_clock::now();
  const double t = std::chrono::duration<double>(
                       std::chrono::steady_clock::now() - start)
                       .count();
  uint64_t bits;
  std::memcpy(&bits, &t, 8);
  ARC_W(c, 0, uint32_t(bits));
  ARC_W(c, 1, uint32_t(bits >> 32));
}

struct Entry {
  const char* cls;
  bool meta;
  const char* sel;
  ArcCtxFn fn;
};

const Entry kEntries[] = {
    {"NSNumber", true, "numberWithInteger:", NumberWithInteger},
    {"NSNumber", true, "numberWithInt:", NumberWithInteger},
    {"NSNumber", true, "numberWithBool:", NumberWithBool},
    {"NSNumber", true, "numberWithFloat:", NumberWithFloat},
    {"NSNumber", false, "intValue", IntValue},
    {"NSNumber", false, "integerValue", IntValue},
    {"NSNumber", false, "floatValue", FloatValue},
    {"NSNumber", false, "boolValue", BoolValue},

    {"NSDictionary", true, "dictionaryWithObjectsAndKeys:",
     DictionaryWithObjectsAndKeys},
    {"NSDictionary", false, "objectForKey:", ObjectForKey},
    {"NSMutableDictionary", false, "objectForKey:", ObjectForKey},
    {"NSMutableDictionary", false, "setObject:forKey:", SetObjectForKey},

    {"NSUserDefaults", true, "standardUserDefaults", StandardUserDefaults},
    {"NSUserDefaults", false, "objectForKey:", ObjectForKey},
    {"NSUserDefaults", false, "setObject:forKey:", SetObjectForKey},
    {"NSUserDefaults", false, "integerForKey:", IntegerForKey},
    {"NSUserDefaults", false, "floatForKey:", FloatForKey},
    {"NSUserDefaults", false, "synchronize", Synchronize},

    {"NSBundle", true, "mainBundle", MainBundle},

    {"UIColor", true, "colorWithRed:green:blue:alpha:", ColorWithRGBA},

    {"NSInvocationOperation", false, "initWithTarget:selector:object:",
     InitWithTargetSelectorObject},
    {"NSOperationQueue", false, "addOperation:", AddOperation},

    {"UIApplication", false, "setStatusBarOrientation:animated:", Nop},
    {"UIApplication", false, "setStatusBarOrientation:", Nop},
    {"UIApplication", false, "setStatusBarHidden:", Nop},
    {"UIApplication", false, "setStatusBarHidden:animated:", Nop},
    {"UIApplication", false, "setIdleTimerDisabled:", Nop},
    // No hardware to read, and a game that asks is entitled to an object it
    // can set a delegate on rather than a nil it will send to anyway.
    {"UIAccelerometer", true, "sharedAccelerometer",
     [](Arm32Ctx* c) { ARC_W(c, 0, Singleton("UIAccelerometer")); }},
    {"UIAccelerometer", false, "setUpdateInterval:", Nop},
    {"UIAccelerometer", false, "setDelegate:", Nop},
    {"UIApplication", true, "sharedApplication", Nop},

    {"NSString", true, "stringWithString:", StringWithString},
    {"NSString", true, "stringWithUTF8String:", StringWithUTF8String},
    {"NSString", true, "stringWithFormat:", StringWithFormat},
    {"NSString", true, "stringWithContentsOfURL:encoding:error:", NilMethod},
    {"NSString", false, "UTF8String", UTF8String},
    {"NSString", false, "floatValue", StringFloatValue},
    {"NSString", false, "intValue", StringIntValue},
    {"NSString", false, "integerValue", StringIntValue},
    {"NSString", false, "doubleValue", StringDoubleValue},
    {"NSString", false, "boolValue", StringBoolValue},
    {"NSString", false, "length", StringLength},
    {"NSString", false, "isEqualToString:", IsEqualToString},
    {"NSMutableString", true, "stringWithFormat:", StringWithFormat},

    {"NSURL", true, "URLWithString:", URLWithString},
    {"AVAudioPlayer", false, "initWithContentsOfURL:error:",
     AudioPlayerInitFailed},
    {"UIDevice", true, "currentDevice", CurrentDevice},

    {"NSBundle", false, "localizedStringForKey:value:table:",
     LocalizedStringForKey},
    {"NSBundle", false, "infoDictionary", ObjectForKey},
    {"NSUserDefaults", false, "registerDefaults:", Nop},
    // A UIColor is its own CGColorRef here: nothing distinguishes them, and
    // the components live on the object either way.
    {"UIColor", false, "CGColor", SelfMethod},

    // Reading a notification's payload off something that is not one. Nothing
    // posts notifications here, so the game is asking about an event that did
    // not happen and nil is the honest answer -- but the receiver being a
    // MenuState rather than an NSNotification says the two sides disagree
    // about something, and this is where to look if that matters later.
    {"NSObject", false, "performSelector:", PerformSelector},
    {"NSObject", false, "performSelector:withObject:", PerformSelector},
    {"NSObject", false, "userInfo", Nop},
    {"NSObject", false, "object", Nop},
    {"NSObject", false, "name", Nop},

    {"NSObject", false, "performSelector:withObject:afterDelay:",
     PerformAfterDelay},
    {"NSObject", false, "copy", SelfMethod},
    {"NSObject", false, "mutableCopy", SelfMethod},
    {"NSBundle", false, "resourcePath", ResourcePath},
    {"NSBundle", false, "bundlePath", ResourcePath},
    {"NSBundle", false, "pathForResource:ofType:", PathForResource},
    {"NSValue", true, "valueWithPointer:", ValueWithPointer},
    {"NSValue", false, "pointerValue", PointerValue},
    {"NSNotificationCenter", true, "defaultCenter", DefaultCenter},
    {"NSNotificationCenter", false,
     "addObserver:selector:name:object:", Nop},
    {"NSNotificationCenter", false, "removeObserver:", Nop},
    {"NSNotificationCenter", false, "postNotificationName:object:", Nop},
    {"UIImageView", false, "initWithImage:", SelfMethod},
    {"UIDevice", false, "uniqueIdentifier", ResourcePath},
    {"UIDevice", false, "systemVersion", ResourcePath},
    {"NSString", false, "stringByAppendingFormat:", SelfMethod},
    {"NSString", false, "stringByAppendingString:", SelfMethod},
    {"NSMutableString", false, "appendString:", Nop},
    {"NSMutableString", false, "appendFormat:", Nop},
    {"NSArray", true, "array", ArrayNew},
    {"NSArray", true, "arrayWithObject:", ArrayWithObject},
    {"NSArray", true, "arrayWithObjects:", ArrayWithObjects},
    {"NSArray", true, "arrayWithArray:", ArrayWithArray},
    {"NSArray", false, "initWithArray:", ArrayInitWithArray},
    {"NSArray", false, "count", ArrayCount},
    {"NSArray", false, "objectAtIndex:", ArrayObjectAtIndex},
    {"NSArray", false, "lastObject", ArrayLastObject},
    {"NSArray", false, "anyObject", ArrayAnyObject},
    {"NSArray", false, "objectEnumerator", ArrayObjectEnumerator},
    {"NSEnumerator", false, "nextObject", EnumeratorNextObject},

    {"NSSet", true, "set", SetNew},
    {"NSSet", true, "setWithSet:", SetWithCollection},
    {"NSSet", true, "setWithArray:", SetWithCollection},
    {"NSSet", true, "setWithObject:", SetWithCollection},
    {"NSSet", false, "initWithSet:", SetInitWithCollection},
    {"NSSet", false, "initWithArray:", SetInitWithCollection},
    {"NSSet", false, "count", ArrayCount},
    {"NSSet", false, "anyObject", ArrayAnyObject},
    {"NSSet", false, "allObjects", SetWithCollection},
    {"NSSet", false, "containsObject:", ArrayContains},
    {"NSSet", false, "member:", ArrayContains},
    {"NSSet", false, "objectEnumerator", ArrayObjectEnumerator},
    {"NSSet", false, "countByEnumeratingWithState:objects:count:",
     CountByEnumerating},
    {"NSMutableSet", true, "set", SetNew},
    {"NSMutableSet", true, "setWithCapacity:", SetNew},
    {"NSMutableSet", true, "setWithSet:", SetWithCollection},
    {"NSMutableSet", true, "setWithArray:", SetWithCollection},
    {"NSMutableSet", false, "addObject:", SetAddObject},
    {"NSMutableSet", false, "addObjectsFromArray:", SetUnion},
    {"NSMutableSet", false, "unionSet:", SetUnion},
    {"NSMutableSet", false, "minusSet:", SetMinus},
    {"NSMutableSet", false, "intersectSet:", SetUnion},
    {"NSMutableSet", false, "removeObject:", ArrayRemoveObject},
    {"NSMutableSet", false, "removeAllObjects", ArrayRemoveAll},
    {"NSArray", false, "containsObject:", ArrayContains},
    {"NSArray", false, "countByEnumeratingWithState:objects:count:",
     CountByEnumerating},
    {"NSMutableArray", true, "array", ArrayNew},
    {"NSMutableArray", true, "arrayWithCapacity:", ArrayNew},
    {"NSMutableArray", false, "addObject:", ArrayAddObject},
    {"NSMutableArray", false, "addObjectsFromArray:",
     ArrayAddObjectsFromArray},
    {"NSMutableArray", false, "removeObject:", ArrayRemoveObject},
    {"NSMutableArray", false, "removeAllObjects", ArrayRemoveAll},

    {"NSString", false, "getCharacters:", GetCharacters},
    {"NSString", false, "characterAtIndex:", CharacterAtIndex},
    {"NSString", false, "rangeOfCharacterFromSet:options:range:",
     RangeOfCharacterFromSet},
    {"NSString", false, "rangeOfCharacterFromSet:", RangeOfCharacterFromSet},
    {"NSCharacterSet", true, "newlineCharacterSet", NewlineCharacterSet},
    {"NSCharacterSet", true, "whitespaceCharacterSet", NewlineCharacterSet},
    {"NSCharacterSet", true, "whitespaceAndNewlineCharacterSet",
     NewlineCharacterSet},
    {"NSCharacterSet", true, "punctuationCharacterSet",
     NewlineCharacterSet},

    // CoreData is the high-score store, and there is no store. Every one of
    // these answering nil gives the game an empty score list, which it
    // handles -- it is the state a first launch is in.
    {"NSEntityDescription", true, "entityForName:inManagedObjectContext:", Nop},
    {"NSEntityDescription", true, "insertNewObjectForEntityForName:"
                                  "inManagedObjectContext:", Nop},
    {"NSFetchRequest", false, "setEntity:", Nop},
    {"NSFetchRequest", false, "setSortDescriptors:", Nop},
    {"NSFetchRequest", false, "setFetchLimit:", Nop},
    {"NSManagedObjectContext", false, "executeFetchRequest:error:", Nop},
    {"NSManagedObjectContext", false, "save:", Nop},
    {"NSManagedObjectContext", false, "deleteObject:", Nop},
    {"NSManagedObjectContext", false,
     "setPersistentStoreCoordinator:", Nop},
    {"NSManagedObjectModel", true, "mergedModelFromBundles:", Nop},
    {"NSPersistentStoreCoordinator", false, "initWithManagedObjectModel:", Nop},
    {"NSPersistentStoreCoordinator", false,
     "addPersistentStoreWithType:configuration:URL:options:error:", Nop},
    {"NSSortDescriptor", false, "initWithKey:ascending:", Nop},
};

struct CImport {
  const char* name;
  ArcCtxFn fn;
};

const CImport kCImports[] = {
    {"_NSLog", NSLogShim},
    {"_NSSearchPathForDirectoriesInDomains", SearchPathForDirectories},
    {"_NSStringFromClass", StringFromClass},
    {"_NSClassFromString", ClassFromString},
    {"_CFAbsoluteTimeGetCurrent", AbsoluteTimeGetCurrent},
    {"_CGColorGetNumberOfComponents", ColorNumberOfComponents},
    {"_CGColorGetComponents", ColorComponents},
};

}  // namespace

// Run everything queued. Nothing calls this yet -- it wants a run loop, which
// wants a window -- but the operations are kept rather than dropped so that
// turning it on later is one call and not a rewrite.
size_t DrainOperations(Arm32Ctx* c) {
  size_t ran = 0;
  std::vector<uint32_t> batch;
  batch.swap(Queued());
  for (const uint32_t op : batch) {
    auto it = Fields().find(op);
    if (it == Fields().end()) continue;
    const uint32_t target = it->second["target"];
    const uint32_t sel = it->second["selector"];
    if (!target || !sel) continue;
    ARC_W(c, 0, target);
    ARC_W(c, 1, sel);
    ARC_W(c, 2, it->second["object"]);
    const char* name = reinterpret_cast<const char*>(uintptr_t(sel));
    if (const uint32_t imp = Objc().Lookup(ARC_LD32(target), name)) {
      arc_dispatch(c, imp);
      ++ran;
    }
  }
  return ran;
}

// Everything whose delay has run out, sent now. The run loop calls this once a
// frame, which is the granularity a device's run loop would have given it too.
size_t RunDuePerforms(Arm32Ctx* c) {
  const auto now = std::chrono::steady_clock::now();
  std::vector<Perform> due, later;
  for (const auto& p : Performs()) (p.due <= now ? due : later).push_back(p);
  Performs().swap(later);
  for (const auto& p : due) {
    const char* name = reinterpret_cast<const char*>(uintptr_t(p.sel));
    const uint32_t imp = Objc().Lookup(ARC_LD32(p.target), name);
    if (!imp) continue;
    const uint32_t sp = ARC_SP(c);
    ARC_W(c, 13, sp - 16);
    ARC_W(c, 0, p.target);
    ARC_W(c, 1, p.sel);
    ARC_W(c, 2, p.object);
    arc_dispatch(c, imp);
    ARC_W(c, 13, sp);
  }
  return due.size();
}

// For the named colours, which are made elsewhere and still have to answer
// what they are made of.
void HostSetColor(uint32_t obj, float r, float g, float b, float a) {
  SetColorComponents(obj, r, g, b, a);
}

// A collection holding one object, for a shim that has to hand the guest a set
// -- the touches UIKit delivers, above all. It is an NSArray, which answers
// everything a one-element NSSet is asked.
uint32_t HostSetOf(uint32_t element) {
  const uint32_t a = MakeArray("NSMutableArray");
  if (a) {
    Arrays()[a].clear();
    if (element) Arrays()[a].push_back(element);
  }
  return a;
}

// The one string reader, shared. Anything holding text -- a literal the
// compiler emitted or a string a shim made -- is read the same way, and the
// image loader needs it to turn `imageNamed:` into a filename.
std::string GuestStringText(uint32_t obj) { return StringText(obj); }

namespace {
void ResourcePath(Arm32Ctx* c) { ARC_W(c, 0, MakeString(BundlePath())); }

void PathForResource(Arm32Ctx* c) {
  const std::string name = StringText(ARC_R(c, 2));
  const std::string type = StringText(ARC_R(c, 3));
  if (name.empty()) {
    ARC_W(c, 0, 0);
    return;
  }
  std::string path = BundlePath() + "/" + name;
  if (!type.empty() && name.rfind("." + type) != name.size() - type.size() - 1)
    path += "." + type;
  if (std::FILE* f = std::fopen(path.c_str(), "rb")) {
    std::fclose(f);
    ARC_W(c, 0, MakeString(path));
    return;
  }
  ARC_W(c, 0, 0);
}
}  // namespace

// Where the .app's resources are. Set by the host, because only it knows.
std::string& BundlePathRef() {
  static std::string path = ".";
  return path;
}

std::string BundlePath() { return BundlePathRef(); }
void SetBundlePath(const std::string& p) { BundlePathRef() = p; }

size_t InstallFoundationCImports(const MachOImage& img) {
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const auto& e : kCImports)
      if (im.name == e.name) {
        arc_register_ctx_native(im.stub, e.name, e.fn);
        ++claimed;
      }
  }
  return claimed;
}

void InstallObjectShims() {
  for (const auto& e : kEntries) {
    HostClass(e.cls, HostSuperOf(e.cls));
    HostMethod(e.cls, e.meta, e.sel, e.fn);
  }
}

}  // namespace arc
