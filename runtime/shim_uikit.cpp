// The window, the view, and the loop that drives them.
//
// iPhone OS handed the app a UIWindow, a UIView whose layer was a
// CAEAGLLayer, and a CADisplayLink calling one selector per refresh. The
// replacement is one SDL window and a loop that calls the same selector -- and
// because that selector's implementation is lifted code, the game's own frame
// runs unchanged.
//
// The awkward part is not the objects, it is the calling convention. A CGRect
// is four floats, which is too big to return in a register, so `-bounds` comes
// through objc_msgSend_stret with a hidden pointer in r0 -- and the same rect
// passed *in* occupies four argument words. Both directions are here.
#include <cstdio>
#include <cstring>
#include <map>
#include <string>

#include "arc_mem.h"
#include "arm32_context.h"
#include "objc_host.h"
#include "objc_runtime.h"
#include "window.h"

namespace arc {

size_t DrainOperations(Arm32Ctx* c);

namespace {

// The device this pretends to be. An iPhone of the era reported its screen in
// portrait whatever the app did, and Canabalt asks for landscape and rotates
// its own projection, so these are deliberately not the window's dimensions.
constexpr int kScreenWidth = 320;
constexpr int kScreenHeight = 480;
constexpr int kWindowWidth = 480;
constexpr int kWindowHeight = 320;

uint32_t Bits(float f) {
  uint32_t u;
  std::memcpy(&u, &f, 4);
  return u;
}

// A CGRect returned by value: too large for a register, so the caller passes a
// hidden pointer in r0 and the callee fills it. objc_msgSend_stret is the
// whole reason that path exists.
void ReturnRect(Arm32Ctx* c, float x, float y, float w, float h) {
  const uint32_t out = ARC_R(c, 0);
  if (!out) return;
  ARC_ST32(out + 0, Bits(x));
  ARC_ST32(out + 4, Bits(y));
  ARC_ST32(out + 8, Bits(w));
  ARC_ST32(out + 12, Bits(h));
}

std::map<uint32_t, std::map<std::string, uint32_t>>& Ivars() {
  static std::map<uint32_t, std::map<std::string, uint32_t>> m;
  return m;
}

uint32_t Singleton(const char* name) {
  static std::map<std::string, uint32_t> made;
  auto it = made.find(name);
  if (it != made.end()) return it->second;
  const uint32_t obj = HostAllocInstance(HostClass(name, "NSObject"));
  made[name] = obj;
  return obj;
}

// --- screen, window, view --------------------------------------------------

void MainScreen(Arm32Ctx* c) { ARC_W(c, 0, Singleton("UIScreen")); }

void ScreenBounds(Arm32Ctx* c) {
  ReturnRect(c, 0, 0, float(kScreenWidth), float(kScreenHeight));
}

void ViewBounds(Arm32Ctx* c) {
  ReturnRect(c, 0, 0, float(WindowWidth() ? WindowWidth() : kWindowWidth),
             float(WindowHeight() ? WindowHeight() : kWindowHeight));
}

// -initWithFrame: on UIView is where FlxGLView's own [super initWithFrame:]
// lands. Returning self is the whole contract: the subclass does the rest,
// and all of that is lifted code.
void InitWithFrame(Arm32Ctx* c) { /* r0 already holds self */ }

void MakeKeyAndVisible(Arm32Ctx* c) {
  // The first time anything asks to be visible, there is a window to be
  // visible in. Opening it here rather than at startup means a run that never
  // gets this far never flashes one up.
  if (!WindowIsOpen())
    WindowOpen(kWindowWidth, kWindowHeight, "Canabalt (iparecomp)");
  ARC_W(c, 0, 0);
}

void SelfMethod(Arm32Ctx*) {}
void NilMethod(Arm32Ctx* c) { ARC_W(c, 0, 0); }

void Layer(Arm32Ctx* c) {
  // Every view has a layer, and for the GL view it is a CAEAGLLayer. Nothing
  // reads anything out of it except to set drawable properties, which go
  // nowhere.
  const uint32_t self = ARC_R(c, 0);
  auto& iv = Ivars()[self];
  if (!iv["layer"])
    iv["layer"] = HostAllocInstance(HostClass("CAEAGLLayer", "NSObject"));
  ARC_W(c, 0, iv["layer"]);
}

// --- colours ---------------------------------------------------------------
// These have to be UIColor instances, not instances of a class invented to
// hold them. Anything sent to a colour afterwards -- `CGColor` here -- is
// looked up on the receiver's own class, so a stand-in class answers nothing.
uint32_t NamedColor(const char* which) {
  static std::map<std::string, uint32_t> made;
  auto it = made.find(which);
  if (it != made.end()) return it->second;
  const uint32_t obj = HostAllocInstance(HostClass("UIColor", "NSObject"));
  made[which] = obj;
  return obj;
}

void WhiteColor(Arm32Ctx* c) { ARC_W(c, 0, NamedColor("white")); }
void BlackColor(Arm32Ctx* c) { ARC_W(c, 0, NamedColor("black")); }

// --- EAGL ------------------------------------------------------------------
// The context is real on a device and irrelevant here: SDL already made one
// and made it current, so these only have to agree that it worked.
void ContextAlloc(Arm32Ctx* c) {
  ARC_W(c, 0, HostAllocInstance(HostClass("EAGLContext", "NSObject")));
}
void SetCurrentContext(Arm32Ctx* c) { ARC_W(c, 0, 1); }
void RenderbufferStorage(Arm32Ctx* c) {
  if (!WindowIsOpen())
    WindowOpen(kWindowWidth, kWindowHeight, "Canabalt (iparecomp)");
  ARC_W(c, 0, 1);
}
void PresentRenderbuffer(Arm32Ctx* c) {
  WindowPresent();
  ARC_W(c, 0, 1);
}

// --- the frame loop --------------------------------------------------------

uint32_t g_link_target = 0;
uint32_t g_link_selector = 0;

void DisplayLinkWithTargetSelector(Arm32Ctx* c) {
  const uint32_t obj =
      HostAllocInstance(HostClass("CADisplayLink", "NSObject"));
  g_link_target = ARC_R(c, 2);
  g_link_selector = ARC_R(c, 3);
  ARC_W(c, 0, obj);
}

void CurrentRunLoop(Arm32Ctx* c) { ARC_W(c, 0, Singleton("NSRunLoop")); }

// -[NSRunLoop run] does not return on a device. Here it must, or there is
// nothing to report afterwards -- so it ends when the window closes, and the
// frame count is capped so a run that never draws still finishes.
void RunLoopRun(Arm32Ctx* c) {
  if (!WindowIsOpen())
    WindowOpen(kWindowWidth, kWindowHeight, "Canabalt (iparecomp)");
  if (!g_link_target || !g_link_selector) {
    std::printf("run loop: nothing registered a display link\n");
    ARC_W(c, 0, 0);
    return;
  }
  const char* sel =
      reinterpret_cast<const char*>(uintptr_t(g_link_selector));
  const uint32_t cls = ARC_LD32(g_link_target);
  const uint32_t imp = Objc().Lookup(cls, sel);
  if (!imp) {
    std::printf("run loop: nothing implements %s\n", sel ? sel : "?");
    ARC_W(c, 0, 0);
    return;
  }
  std::printf("run loop: driving %s\n", sel);
  // Reaching here is the thing the budget was guarding; from now on entering
  // functions forever is the point.
  arc_frame_budget(0);

  // Anything queued during launch runs before the first frame, which is where
  // a device would have got to it too.
  DrainOperations(c);

  const long kMaxFrames = 100000;
  long frames = 0;
  while (WindowIsOpen() && frames < kMaxFrames) {
    ARC_W(c, 0, g_link_target);
    ARC_W(c, 1, g_link_selector);
    arc_dispatch(c, imp);
    if (!WindowPresent()) break;
    ++frames;
  }
  std::printf("run loop: %ld frames\n", frames);
  ARC_W(c, 0, 0);
}

struct Entry {
  const char* cls;
  bool meta;
  const char* sel;
  ArcCtxFn fn;
};

const Entry kEntries[] = {
    {"UIScreen", true, "mainScreen", MainScreen},
    {"UIScreen", false, "bounds", ScreenBounds},
    {"UIScreen", false, "applicationFrame", ScreenBounds},

    {"UIWindow", false, "initWithFrame:", InitWithFrame},
    {"UIWindow", false, "makeKeyAndVisible", MakeKeyAndVisible},
    {"UIWindow", false, "addSubview:", NilMethod},
    {"UIWindow", false, "bounds", ViewBounds},
    {"UIWindow", false, "setRootViewController:", NilMethod},

    {"UIView", false, "initWithFrame:", InitWithFrame},
    {"UIView", false, "bounds", ViewBounds},
    {"UIView", false, "frame", ViewBounds},
    {"UIView", false, "addSubview:", NilMethod},
    {"UIView", false, "layer", Layer},
    {"UIView", false, "setMultipleTouchEnabled:", NilMethod},
    {"UIView", false, "setUserInteractionEnabled:", NilMethod},
    {"UIView", true, "beginAnimations:context:", NilMethod},
    {"UIView", true, "setAnimationDuration:", NilMethod},
    {"UIView", true, "setAnimationDelegate:", NilMethod},
    {"UIView", true, "setAnimationDidStopSelector:", NilMethod},
    {"UIView", true, "commitAnimations", NilMethod},

    // The ordinary view properties. A game sets these on things it is about
    // to draw itself with GL, so accepting and ignoring them is not a
    // shortcut -- nothing here composites UIViews.
    {"UIView", false, "setAlpha:", NilMethod},
    {"UIView", false, "setHidden:", NilMethod},
    {"UIView", false, "setFrame:", NilMethod},
    {"UIView", false, "setCenter:", NilMethod},
    {"UIView", false, "setBounds:", NilMethod},
    {"UIView", false, "setOpaque:", NilMethod},
    {"UIView", false, "setBackgroundColor:", NilMethod},
    {"UIView", false, "setClipsToBounds:", NilMethod},
    {"UIView", false, "setContentMode:", NilMethod},
    {"UIView", false, "setTransform:", NilMethod},
    {"UIView", false, "setAutoresizingMask:", NilMethod},
    {"UIView", false, "setTag:", NilMethod},
    {"UIView", false, "setNeedsDisplay", NilMethod},
    {"UIView", false, "setNeedsLayout", NilMethod},
    {"UIView", false, "layoutSubviews", NilMethod},
    {"UIView", false, "sizeToFit", NilMethod},
    {"UIView", false, "setNeedsDisplayInRect:", NilMethod},
    {"UIView", false, "setContentScaleFactor:", NilMethod},
    {"UIView", false, "removeFromSuperview", NilMethod},
    {"UIView", false, "superview", NilMethod},
    {"UIView", false, "alpha", NilMethod},
    {"UIView", false, "hidden", NilMethod},
    {"UIView", false, "bringSubviewToFront:", NilMethod},
    {"UIView", false, "sendSubviewToBack:", NilMethod},
    {"UIImageView", false, "setImage:", NilMethod},
    {"UIImageView", false, "initWithFrame:", InitWithFrame},

    {"UIColor", true, "whiteColor", WhiteColor},
    {"UIColor", true, "blackColor", BlackColor},

    {"CAEAGLLayer", false, "setOpaque:", NilMethod},
    {"CAEAGLLayer", false, "setDrawableProperties:", NilMethod},

    {"EAGLContext", true, "alloc", ContextAlloc},
    {"EAGLContext", false, "initWithAPI:", SelfMethod},
    {"EAGLContext", true, "setCurrentContext:", SetCurrentContext},
    {"EAGLContext", false, "renderbufferStorage:fromDrawable:",
     RenderbufferStorage},
    {"EAGLContext", false, "presentRenderbuffer:", PresentRenderbuffer},

    {"CADisplayLink", true, "displayLinkWithTarget:selector:",
     DisplayLinkWithTargetSelector},
    {"CADisplayLink", false, "setFrameInterval:", NilMethod},
    {"CADisplayLink", false, "addToRunLoop:forMode:", NilMethod},
    {"CADisplayLink", false, "invalidate", NilMethod},

    {"NSRunLoop", true, "currentRunLoop", CurrentRunLoop},
    {"NSRunLoop", true, "mainRunLoop", CurrentRunLoop},
    {"NSRunLoop", false, "run", RunLoopRun},

    {"NSNotificationCenter", true, "defaultCenter", NilMethod},
    {"NSValue", true, "valueWithPointer:", NilMethod},
};

}  // namespace

// The hierarchy has to be declared before anything else names these classes.
// HostClass returns an existing class rather than re-parenting one, so
// whichever call happens first decides the superclass -- and a shim table
// mentioning UIImageView in passing would otherwise root it at NSObject and
// quietly cut it off from every method UIView owns.
void InstallClassHierarchy() {
  static const struct { const char* cls; const char* super; } kTree[] = {
      {"UIResponder", "NSObject"},
      {"UIView", "UIResponder"},
      {"UIWindow", "UIView"},
      {"UIImageView", "UIView"},
      {"UIScrollView", "UIView"},
      {"UIButton", "UIView"},
      {"UITextField", "UIView"},
      {"UIActivityIndicatorView", "UIView"},
      {"UIViewController", "UIResponder"},
      {"UIApplication", "UIResponder"},
  };
  for (const auto& t : kTree) HostClass(t.cls, t.super);
}

void InstallUIKitObjects() {
  for (const auto& e : kEntries) {
    HostClass(e.cls, "NSObject");
    HostMethod(e.cls, e.meta, e.sel, e.fn);
  }
}

}  // namespace arc
