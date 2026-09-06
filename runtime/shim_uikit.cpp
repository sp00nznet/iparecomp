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
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "arc_mem.h"
#include "arm32_context.h"
#include "objc_host.h"
#include "objc_runtime.h"
#include "window.h"

namespace arc {

size_t DrainOperations(Arm32Ctx* c);
uint32_t HostSetOf(uint32_t element);
void HostSetColor(uint32_t obj, float r, float g, float b, float a);
size_t RunDuePerforms(Arm32Ctx* c);

// The view that answers touches, remembered when it is framed -- see the
// touches section below, which is where it is used.
extern uint32_t g_touch_view;

// Defined below, and called from UIApplicationMain as well as from
// -[NSRunLoop run]: on a device UIApplicationMain never returns, and an app
// that expects that never asks for a run loop of its own. Canabalt does not.
void RunFrameLoop(Arm32Ctx* c);

namespace {

// The device this pretends to be. An iPhone of the era reported its screen in
// portrait whatever the app did, and Canabalt asks for landscape and rotates
// its own projection, so these are deliberately not the window's dimensions.
constexpr int kScreenWidth = 320;
constexpr int kScreenHeight = 480;
// The window is the device's framebuffer, and the device's framebuffer is
// portrait. A landscape game rotates its own content into it -- Canabalt sets
// up `glOrthof(0, backingWidth, backingHeight, 0)` and then
// `translate(w/2, h/2); rotate(90); translate(-h/2, -w/2)` -- so handing it a
// landscape one makes it rotate a second time and everything lands off the
// bottom of the screen. The backing size is read back through
// `glGetRenderbufferParameterivOES`, which is why this is the number that
// decides it.
// The window is landscape, because that is how the game is meant to be seen.
// The guest is still told its framebuffer is portrait -- see the quarter turn
// in shim_gl -- so its own transform chain is the device's, untouched.
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
  if (!SendingStret()) {
    arc_trap(c, "a rectangle-returning method was reached through the ordinary "
                "objc_msgSend; writing the result would land on the receiver");
    return;
  }
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

// A CGPoint is two floats and still comes through objc_msgSend_stret -- the
// trail says so, which is the only reliable way to tell. Under stret the
// hidden pointer takes r0 and the receiver moves to r1.
void ReturnPoint(Arm32Ctx* c, float x, float y) {
  if (!SendingStret()) {
    arc_trap(c, "a point-returning method was reached through the ordinary "
                "objc_msgSend; writing the result would land on the receiver");
    return;
  }
  const uint32_t out = ARC_R(c, 0);
  if (!out) return;
  ARC_ST32(out + 0, Bits(x));
  ARC_ST32(out + 4, Bits(y));
}

// A view's frame is its own, not the screen's. Answering every `-frame` with
// the window's rect is fine for the one full-screen GL view and wrong for
// everything else: Canabalt's SSText is a UIView subclass, and it centres its
// glyphs in `frame.size`. Told the frame was 320x480 when the text's own
// bitmap is 128x32, it put the pen at x=132 and every glyph fell outside the
// texture -- which uploaded blank, and drew as nothing.
//
// So the rect a view is given is kept. A view nobody framed still gets the
// window, because the full-screen view is exactly the one that never sets one.
struct Rect {
  float x = 0, y = 0, w = 0, h = 0;
};

std::map<uint32_t, Rect>& Frames() {
  static std::map<uint32_t, Rect> m;
  return m;
}

float ArgF(Arm32Ctx* c, int i) {
  const uint32_t bits =
      i < 4 ? ARC_R(c, uint32_t(i)) : ARC_LD32(ARC_SP(c) + uint32_t(i - 4) * 4);
  float f;
  std::memcpy(&f, &bits, 4);
  return f;
}

Rect FrameOf(uint32_t obj) {
  auto it = Frames().find(obj);
  if (it != Frames().end()) return it->second;
  Rect r;
  r.w = float(kScreenWidth);
  r.h = float(kScreenHeight);
  return r;
}

// A CGRect argument to a method occupies r2, r3 and then the stack, because
// r0 and r1 are already self and _cmd.
void TakeFrame(Arm32Ctx* c) {
  Rect r;
  r.x = ArgF(c, 2);
  r.y = ArgF(c, 3);
  r.w = ArgF(c, 4);
  r.h = ArgF(c, 5);
  if (ARC_R(c, 0)) Frames()[ARC_R(c, 0)] = r;
}

void ViewCenter(Arm32Ctx* c) {
  const Rect r = FrameOf(ARC_R(c, 1));  // stret: the receiver is in r1
  ReturnPoint(c, r.x + r.w / 2, r.y + r.h / 2);
}

// -bounds is the frame's size at the origin; -frame keeps its position.
void ViewBounds(Arm32Ctx* c) {
  const Rect r = FrameOf(ARC_R(c, 1));
  ReturnRect(c, 0, 0, r.w, r.h);
}

void ViewFrame(Arm32Ctx* c) {
  const Rect r = FrameOf(ARC_R(c, 1));
  ReturnRect(c, r.x, r.y, r.w, r.h);
}

void SetFrame(Arm32Ctx* c) {
  TakeFrame(c);
  ARC_W(c, 0, 0);
}

// -initWithFrame: on UIView is where FlxGLView's own [super initWithFrame:]
// lands. Returning self is the whole contract -- the subclass does the rest,
// and all of that is lifted code -- but the rect it was given is kept.
void InitWithFrame(Arm32Ctx* c) {
  TakeFrame(c);
  // The touch target, caught on its way past: see DeliverTouch.
  const uint32_t self = ARC_R(c, 0);
  if (self && Objc().Lookup(ARC_LD32(self), "touchesBegan:withEvent:"))
    g_touch_view = self;
  /* r0 already holds self */
}

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
//
// Every `+xxxColor` is the same shape -- a token that has to be a distinct,
// stable UIColor instance and carries no components anything here reads -- so
// one handler covers the whole set. The selector pointer in r1 is already a
// unique key for the name, which saves both a thunk per colour and a way to
// turn a selector back into a string.
//
// ponytail: no components. When something asks a colour what it is made of,
// give this map an RGBA and answer `getRed:green:blue:alpha:` from it.
void SomeColor(Arm32Ctx* c) {
  static std::map<uint32_t, uint32_t> made;
  const uint32_t sel = ARC_R(c, 1);
  uint32_t& obj = made[sel];
  if (!obj) {
    obj = HostAllocInstance(HostClass("UIColor", "NSObject"));
    // The components, because something does eventually ask: a colour with
    // none is refused by `-[FlxTexture initWithColor:]` with "invalid
    // component count". The selector's own name is the key, and an unknown
    // one is opaque white rather than nothing.
    static const struct {
      const char* sel;
      float r, g, b, a;
    } kColors[] = {
        {"whiteColor", 1, 1, 1, 1},        {"blackColor", 0, 0, 0, 1},
        {"grayColor", .5f, .5f, .5f, 1},   {"darkGrayColor", .33f, .33f, .33f, 1},
        {"lightGrayColor", .66f, .66f, .66f, 1}, {"clearColor", 0, 0, 0, 0},
        {"redColor", 1, 0, 0, 1},          {"greenColor", 0, 1, 0, 1},
        {"blueColor", 0, 0, 1, 1},         {"cyanColor", 0, 1, 1, 1},
        {"yellowColor", 1, 1, 0, 1},       {"magentaColor", 1, 0, 1, 1},
        {"orangeColor", 1, .5f, 0, 1},     {"purpleColor", .5f, 0, .5f, 1},
        {"brownColor", .6f, .4f, .2f, 1},
    };
    const char* name = reinterpret_cast<const char*>(uintptr_t(sel));
    float r = 1, g = 1, b = 1, a = 1;
    if (name)
      for (const auto& k : kColors)
        if (std::strcmp(name, k.sel) == 0) {
          r = k.r;
          g = k.g;
          b = k.b;
          a = k.a;
          break;
        }
    HostSetColor(obj, r, g, b, a);
  }
  ARC_W(c, 0, obj);
}

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

// --- animations ------------------------------------------------------------
// A UIView animation block is a delegate, a selector and a duration, and the
// part that matters here is that the selector runs -- eventually, and not
// before. Canabalt's splash fade ends in
// `-[FlxGame fadeDefaultViewAnimation:finished:context:]`, which sets
// `logoComplete`; until that is set, `gameLoop` clears the screen, presents
// it, and does nothing else. A frame loop that runs perfectly and draws
// nothing looks exactly like a broken renderer.
//
// Running the completion inline at `commitAnimations` was the first attempt
// and it was wrong for the same reason inline NSOperations were: the
// animation is asynchronous, so the callback landed *before*
// `-[FlxGame initWithState:orientation:backgroundColor:]`, which zeroes
// `logoComplete` on the way past. Setting a flag and then having the object
// that owns it constructed afterwards is not a race the real order has.
//
// So the completion waits out its own duration and fires from the frame loop.
// Nothing here interpolates a view property -- the splash image is never
// drawn -- but the clock is the thing that keeps the ordering honest, and it
// is also the knob to turn if a title's timing needs it.
struct Animation {
  uint32_t delegate = 0, stop_sel = 0, id = 0, context = 0;
  double duration = 0;
};

Animation g_anim;                 // the block being built
Animation g_pending;              // committed, waiting for its clock
std::chrono::steady_clock::time_point g_pending_due;
bool g_has_pending = false;

void BeginAnimations(Arm32Ctx* c) {
  g_anim = Animation();
  g_anim.id = ARC_R(c, 2);
  g_anim.context = ARC_R(c, 3);
}

// The duration is a double in r2/r3 under softfp.
void SetAnimationDuration(Arm32Ctx* c) {
  const uint64_t bits = uint64_t(ARC_R(c, 2)) | (uint64_t(ARC_R(c, 3)) << 32);
  double d;
  std::memcpy(&d, &bits, 8);
  g_anim.duration = (d > 0 && d < 60) ? d : 0;
}

void SetAnimationDelegate(Arm32Ctx* c) { g_anim.delegate = ARC_R(c, 2); }
void SetAnimationDidStopSelector(Arm32Ctx* c) { g_anim.stop_sel = ARC_R(c, 2); }

void CommitAnimations(Arm32Ctx* c) {
  if (g_anim.delegate && g_anim.stop_sel) {
    g_pending = g_anim;
    g_pending_due = std::chrono::steady_clock::now() +
                    std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                        std::chrono::duration<double>(g_anim.duration));
    g_has_pending = true;
  }
  g_anim = Animation();
  ARC_W(c, 0, 0);
}

// animationDidStop:(NSString*)id finished:(NSNumber*)finished context:(void*)
void RunDueAnimations(Arm32Ctx* c) {
  if (!g_has_pending || std::chrono::steady_clock::now() < g_pending_due)
    return;
  const Animation a = g_pending;
  g_has_pending = false;
  const char* name = reinterpret_cast<const char*>(uintptr_t(a.stop_sel));
  const uint32_t imp = Objc().Lookup(ARC_LD32(a.delegate), name);
  if (std::getenv("ARC_TRACE_MSG"))
    std::printf("[anim] %s on %#x -> %#x\n", name ? name : "?", a.delegate,
                imp);
  if (!imp) return;
  const uint32_t sp = ARC_SP(c);
  ARC_W(c, 13, sp - 16);
  ARC_ST32(ARC_SP(c), a.context);
  ARC_W(c, 0, a.delegate);
  ARC_W(c, 1, a.stop_sel);
  ARC_W(c, 2, a.id);
  ARC_W(c, 3, 1);  // finished: YES, because it did
  arc_dispatch(c, imp);
  ARC_W(c, 13, sp);
}

// --- touches ---------------------------------------------------------------
// A mouse is one finger. UIKit delivers a touch as an NSSet of UITouch handed
// to `-touchesBegan:withEvent:` on the view, and Canabalt's FlxGLView passes
// `[event allTouches]` straight to `-[FlxGlobal processTouches:]`. The binary
// asks a touch for exactly one thing -- `locationInView:` -- and never for its
// phase, because which of the three methods was called says that already.
//
// The view is the one that answers `touchesBegan:withEvent:`, remembered when
// it is framed: its own `initWithFrame:` goes through `[super initWithFrame:]`
// and lands here, which is the only moment a shim sees that instance.
uint32_t g_touch = 0;
uint32_t g_touch_set = 0;
uint32_t g_touch_event = 0;
float g_touch_x = 0, g_touch_y = 0;

void TouchLocationInView(Arm32Ctx* c) { ReturnPoint(c, g_touch_x, g_touch_y); }
void EventAllTouches(Arm32Ctx* c) { ARC_W(c, 0, g_touch_set); }

// The window is landscape and the guest's view is the portrait one a device
// has, turned a quarter turn by the projection -- so a point comes back the
// same way. See the quarter turn in shim_gl.
// ARC_TAP="x,y[,frame][;x,y,frame...]" taps the window at those points, in
// window pixels, so that "does the PLAY button start the game" is a question
// that can be asked without a person clicking -- and so that a run through the
// menus is a thing that repeats exactly. Down at `frame` (200 by default), up
// four frames later, because a button wants both halves.
struct Tap {
  float x = 0, y = 0;
  long at = 0;
};

const std::vector<Tap>& Taps() {
  static std::vector<Tap> v;
  static bool parsed = false;
  if (!parsed) {
    parsed = true;
    const char* env = std::getenv("ARC_TAP");
    while (env && *env) {
      Tap t;
      char* end = nullptr;
      t.x = std::strtof(env, &end);
      if (!end || *end != ',') break;
      t.y = std::strtof(end + 1, &end);
      t.at = (end && *end == ',') ? std::strtol(end + 1, &end, 10) : 200;
      v.push_back(t);
      env = (end && *end == ';') ? end + 1 : nullptr;
    }
  }
  return v;
}

Touch ScriptedTouch(long frame) {
  Touch t;
  for (const auto& tap : Taps()) {
    if (frame == tap.at) t = {Touch::kBegan, tap.x, tap.y, true};
    else if (frame == tap.at + 4) t = {Touch::kEnded, tap.x, tap.y, true};
  }
  return t;
}

void DeliverTouch(Arm32Ctx* c, long frame) {
  Touch t = ScriptedTouch(frame);
  if (!t.valid) t = WindowTakeTouch();
  if (!t.valid || !g_touch_view) return;
  if (!g_touch) {
    g_touch = HostAllocInstance(HostClass("UITouch", "NSObject"));
    g_touch_event = HostAllocInstance(HostClass("UIEvent", "NSObject"));
    g_touch_set = HostSetOf(g_touch);
  }
  if (!g_touch || !g_touch_set) return;
  g_touch_x = float(WindowHeight()) - t.y;
  g_touch_y = t.x;

  const char* sel = t.phase == Touch::kBegan   ? "touchesBegan:withEvent:"
                    : t.phase == Touch::kMoved ? "touchesMoved:withEvent:"
                                               : "touchesEnded:withEvent:";
  const uint32_t imp = Objc().Lookup(ARC_LD32(g_touch_view), sel);
  if (!imp) return;
  std::printf("[touch] %s at (%.0f,%.0f)\n", sel, double(g_touch_x),
              double(g_touch_y));
  const uint32_t sp = ARC_SP(c);
  ARC_W(c, 13, sp - 16);
  ARC_W(c, 0, g_touch_view);
  ARC_W(c, 1, 0);  // _cmd, which the implementation does not read
  ARC_W(c, 2, g_touch_set);
  ARC_W(c, 3, g_touch_event);
  arc_dispatch(c, imp);
  ARC_W(c, 13, sp);
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
    {"UIView", false, "frame", ViewFrame},
    {"UIView", false, "addSubview:", NilMethod},
    {"UIView", false, "layer", Layer},
    {"UIView", false, "setMultipleTouchEnabled:", NilMethod},
    {"UIView", false, "setUserInteractionEnabled:", NilMethod},
    {"UIView", true, "beginAnimations:context:", BeginAnimations},
    {"UIView", true, "setAnimationDuration:", SetAnimationDuration},
    {"UIView", true, "setAnimationDelay:", NilMethod},
    {"UIView", true, "setAnimationCurve:", NilMethod},
    {"UIView", true, "setAnimationDelegate:", SetAnimationDelegate},
    {"UIView", true, "setAnimationDidStopSelector:",
     SetAnimationDidStopSelector},
    {"UIView", true, "commitAnimations", CommitAnimations},

    // The ordinary view properties. A game sets these on things it is about
    // to draw itself with GL, so accepting and ignoring them is not a
    // shortcut -- nothing here composites UIViews.
    {"UIView", false, "setAlpha:", NilMethod},
    {"UIView", false, "setHidden:", NilMethod},
    {"UIView", false, "setFrame:", SetFrame},
    {"UIView", false, "setCenter:", NilMethod},
    {"UIView", false, "setBounds:", NilMethod},
    {"UIView", false, "setOpaque:", NilMethod},
    {"UIView", false, "setBackgroundColor:", NilMethod},
    {"UIView", false, "setClipsToBounds:", NilMethod},
    {"UIView", false, "setContentMode:", NilMethod},
    {"UIView", false, "setTransform:", NilMethod},
    {"UIView", false, "setAutoresizingMask:", NilMethod},
    {"UIView", false, "setTag:", NilMethod},
    {"UIView", false, "center", ViewCenter},
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

    // The whole standard set, because the next one asked for is a stop and
    // they all cost the same.
    {"UITouch", false, "locationInView:", TouchLocationInView},
    {"UIEvent", false, "allTouches", EventAllTouches},

    {"UIColor", true, "whiteColor", SomeColor},
    {"UIColor", true, "blackColor", SomeColor},
    {"UIColor", true, "grayColor", SomeColor},
    {"UIColor", true, "darkGrayColor", SomeColor},
    {"UIColor", true, "lightGrayColor", SomeColor},
    {"UIColor", true, "clearColor", SomeColor},
    {"UIColor", true, "redColor", SomeColor},
    {"UIColor", true, "greenColor", SomeColor},
    {"UIColor", true, "blueColor", SomeColor},
    {"UIColor", true, "cyanColor", SomeColor},
    {"UIColor", true, "yellowColor", SomeColor},
    {"UIColor", true, "magentaColor", SomeColor},
    {"UIColor", true, "orangeColor", SomeColor},
    {"UIColor", true, "purpleColor", SomeColor},
    {"UIColor", true, "brownColor", SomeColor},

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
    {"NSRunLoop", false, "run", RunFrameLoop},

    {"NSNotificationCenter", true, "defaultCenter", NilMethod},
    {"NSValue", true, "valueWithPointer:", NilMethod},
};

}  // namespace

// -[NSRunLoop run] does not return on a device. Here it must, or there is
// nothing to report afterwards -- so it ends when the window closes, and the
// frame count is capped so a run that never draws still finishes.
void RunFrameLoop(Arm32Ctx* c) {
  // Once. The guest may ask for a run loop after UIApplicationMain has
  // already entered one, and a frame loop inside a frame loop is not a
  // deeper simulation of anything.
  static bool running = false;
  if (running) {
    ARC_W(c, 0, 0);
    return;
  }
  running = true;

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

  // A run that does not finish reports nothing, and a frame loop is by
  // construction a run that does not finish. `ARC_MAX_FRAMES=n` bounds it, so
  // "does it draw thirty frames without trapping" is a question that can be
  // asked without a person watching a window.
  long limit = 100000;
  if (const char* env = std::getenv("ARC_MAX_FRAMES")) {
    const long n = std::strtol(env, nullptr, 10);
    if (n > 0) limit = n;
  }
  long frames = 0;
  while (WindowIsOpen() && frames < limit) {
    // Anything whose duration has run out fires before the frame that would
    // have seen its effect.
    RunDueAnimations(c);
    RunDuePerforms(c);
    DeliverTouch(c, frames);
    // ARC_SHOT=<path> writes the last frame out, so "does it draw" has an
    // answer that is not a trace. The request is made before the frame runs,
    // because the guest presents it -- see WindowPresent.
    //
    // With ARC_SHOT_EVERY=n it writes every nth frame instead, numbered, and
    // the run becomes a recording: no window chrome, no cursor, and the same
    // frames every time, which a hand-held screen capture is not.
    if (const char* shot = std::getenv("ARC_SHOT")) {
      static long every = -1;
      if (every < 0) {
        const char* e = std::getenv("ARC_SHOT_EVERY");
        every = e ? std::strtol(e, nullptr, 10) : 0;
      }
      if (every > 0) {
        if (frames % every == 0) {
          char path[512];
          std::snprintf(path, sizeof path, "%s.%04ld.ppm", shot,
                        frames / every);
          WindowCaptureNext(path);
        }
      } else if (frames + 1 == limit) {
        WindowCaptureNext(shot);
      }
    }
    ARC_W(c, 0, g_link_target);
    ARC_W(c, 1, g_link_selector);
    arc_dispatch(c, imp);
    if (!WindowPump()) break;
    ++frames;
  }
  std::printf("run loop: %ld frames\n", frames);
  ARC_W(c, 0, 0);
}


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

uint32_t g_touch_view = 0;

}  // namespace arc
