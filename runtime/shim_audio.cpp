// Audio, answered well enough to get past it.
//
// There is no sound here yet and this does not pretend otherwise. What it does
// is answer honestly enough that the game's own audio setup runs to the end
// instead of stopping the launch, because everything after it -- the window,
// the GL surface, the frame loop -- is on the far side.
//
// The distinction that matters is between "succeeded" and "failed", not
// between real and fake. AudioSession is told everything worked, because
// nothing depends on it. Opening a *file* is told it failed, because the
// alternative is worse: a success with a zero length had the game allocate a
// buffer from a size it never got, which showed up as a quarter of a gigabyte
// off the guest heap in one call. A refusal it already handles beats a
// success it cannot.
#include <cstring>

#include "arc_mem.h"
#include "arm32_context.h"
#include "macho_image.h"

namespace arc {
namespace {

// noErr. Every CoreAudio call reports through its return value.
uint32_t Ok(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
            uint32_t, uint32_t) {
  return 0;
}

// kAudioFileUnspecifiedError. Any non-zero would do; this is the one the
// framework actually returns, so a caller matching on it behaves as it would.
uint32_t FileFailed(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t) {
  return 0x7768743F;
}

// A device and a context have to be non-null or the game concludes there is no
// audio hardware and takes a different path -- which is a path with much less
// exercise on it. Better to look ordinary and be silent.
uint32_t OpenHandle(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t) {
  return arc_guest_alloc(16, 8);
}

uint32_t True(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
              uint32_t, uint32_t) {
  return 1;
}

// alGenBuffers(n, out) and alGenSources(n, out) hand back names. They only
// have to be distinct and non-zero.
uint32_t GenNames(uint32_t n, uint32_t out, uint32_t, uint32_t, uint32_t,
                  uint32_t, uint32_t, uint32_t) {
  static uint32_t next = 1;
  if (!out) return 0;
  for (uint32_t i = 0; i < n && i < 1024; ++i) ARC_ST32(out + i * 4, next++);
  return 0;
}

struct Shim {
  const char* name;
  ArcNativeFn fn;
};

const Shim kShims[] = {
    {"_AudioSessionInitialize", Ok},
    {"_AudioSessionSetProperty", Ok},
    {"_AudioSessionGetProperty", Ok},
    {"_AudioSessionSetActive", Ok},
    {"_AudioFileOpenURL", FileFailed},
    {"_AudioFileGetProperty", FileFailed},
    {"_AudioFileReadBytes", FileFailed},
    {"_AudioFileClose", Ok},

    {"_alcOpenDevice", OpenHandle},
    {"_alcCreateContext", OpenHandle},
    {"_alcMakeContextCurrent", True},
    {"_alcDestroyContext", Ok},
    {"_alcCloseDevice", True},
    {"_alcGetProcAddress", Ok},
    {"_alGetError", Ok},
    {"_alGenBuffers", GenNames},
    {"_alGenSources", GenNames},
    {"_alDeleteSources", Ok},
    {"_alSourcei", Ok},
    {"_alSourcef", Ok},
    {"_alSourcePlay", Ok},
    {"_alListener3f", Ok},
};

}  // namespace

size_t InstallAudioShims(const MachOImage& img) {
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const auto& s : kShims)
      if (im.name == s.name) {
        arc_register_native(im.stub, s.name, s.fn);
        ++claimed;
      }
  }
  return claimed;
}

}  // namespace arc
