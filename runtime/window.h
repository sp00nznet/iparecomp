// The window the guest draws into, and the loop that drives it.
//
// iPhone OS gave an app a UIWindow, a GL surface backed by a CAEAGLLayer, and
// a CADisplayLink calling it once per refresh. All three are replaced here by
// one SDL window with a compatibility GL context and a loop that calls the
// display link's target itself.
//
// The GL side is the one place this platform is generous. Every OpenGL ES 1.1
// entry point the game uses is also OpenGL 1.1 under the same name, so the
// shims are direct calls rather than a translation layer -- and an emulator
// would have had to implement the PowerVR MBX instead.
#pragma once

#include <stdint.h>

namespace arc {

// Opens the window and makes its GL context current. Idempotent.
bool WindowOpen(int width, int height, const char* title);
bool WindowIsOpen();

// Present what has been drawn, and take whatever the user did. Returns false
// once the window has been closed, which is how the run loop ends.
//
// Only the guest's own end-of-frame calls this -- `-[EAGLContext
// presentRenderbuffer:]` is where a frame ends on a device, and it is where a
// frame ends here. The run loop pumps instead: swapping a second time after
// the guest has already swapped shows the back buffer, whose contents after a
// swap are undefined, which is a convincing black screen.
bool WindowPresent();

// Take whatever the user did, without presenting. Returns false once the
// window has been closed, which is how the run loop ends.
bool WindowPump();

int WindowWidth();
int WindowHeight();

// Write the next presented frame to `path` as a binary PPM. Answering "does it
// draw" by reading a trace is inference; this is the picture. It happens
// before the buffer swap, because after the swap the back buffer's contents
// are undefined and a screenshot of undefined is a convincing black rectangle.
void WindowCaptureNext(const char* path);

// A touch, translated from the mouse. iPhone OS delivered these to the view as
// a set of UITouch objects; the run loop asks for them here.
struct Touch {
  enum Phase { kBegan, kMoved, kEnded } phase = kBegan;
  float x = 0, y = 0;
  bool valid = false;
};

Touch WindowTakeTouch();

void WindowClose();

}  // namespace arc
