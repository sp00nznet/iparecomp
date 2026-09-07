// Audio, for real this time.
//
// The shape of this is decided by what the guest actually does, which is the
// standard iPhone-era OpenAL recipe and is worth writing down because nothing
// about it is guessable from the import list:
//
//   AudioFileOpenURL(url, kAudioFileReadPermission, 0, &file)
//   AudioFileGetProperty(file, 'dfmt', &size, &asbd)      -- the format
//   AudioFileGetProperty(file, 'bcnt', &size, &bytes)     -- how much PCM
//   AudioFileReadBytes(file, false, 0, &n, data)          -- the PCM itself
//   alGenBuffers(1, &buffer)
//   alcGetProcAddress(NULL, "alBufferDataStatic")(buffer, fmt, data, n, rate)
//   AudioFileClose(file)
//   alSourcei(source, AL_BUFFER, buffer)
//
// `alBufferDataStatic` is the reason `alcGetProcAddress` is in the import
// list at all: it is an Apple extension, not core OpenAL, so it has no import
// of its own and is fetched by name at run time. Returning null from
// alcGetProcAddress -- which is what "answer zero and move on" does -- leaves
// the game with a null function pointer it never checks.
//
// Static, in that extension's sense, means the buffer does not copy: OpenAL
// keeps the caller's pointer. Here that pointer is guest memory, and the guest
// frees it right after AudioFileClose in some paths, so this copies anyway.
// The name is about ownership, and getting it wrong is a use-after-free that
// only shows up as noise in the mix.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "arc_mem.h"
#include "arm32_context.h"
#include "macho_image.h"

#if defined(ARC_HAVE_SDL2)
#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>
#endif

namespace arc {

std::string GuestStringText(uint32_t obj);

namespace {

// --- the file format -------------------------------------------------------
//
// CAF is a big-endian *container*, chunked, and the two chunks that matter are
// `desc` (the format, always immediately after the 8-byte header) and `data`
// (the samples, after a 4-byte edit-count field). Canabalt's 29 files are all
// 16-bit mono LPCM at 22050 Hz, and they are little-endian -- see the flag
// trap below, which is the one thing about this format worth knowing.

uint32_t Be32(const uint8_t* p) {
  return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
uint64_t Be64(const uint8_t* p) {
  return uint64_t(Be32(p)) << 32 | Be32(p + 4);
}

struct Sound {
  double rate = 22050.0;
  uint32_t channels = 1;
  uint32_t bits = 16;
  bool big_endian = false;
  std::vector<uint8_t> pcm;      // as it sits in the file
  bool ok = false;
};

Sound ReadCaf(const std::string& path) {
  Sound s;
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return s;
  std::vector<uint8_t> all;
  std::fseek(f, 0, SEEK_END);
  const long size = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (size > 0) {
    all.resize(size_t(size));
    if (std::fread(all.data(), 1, all.size(), f) != all.size()) all.clear();
  }
  std::fclose(f);
  if (all.size() < 8 || std::memcmp(all.data(), "caff", 4) != 0) return s;

  size_t p = 8;
  while (p + 12 <= all.size()) {
    const uint8_t* h = all.data() + p;
    const uint64_t len = Be64(h + 4);
    const size_t body = p + 12;
    if (len > all.size() || body + len > all.size()) {
      // A `data` chunk is allowed to declare -1 for "to the end of file",
      // which is the one length that legitimately overruns.
      if (std::memcmp(h, "data", 4) == 0 && body + 4 <= all.size()) {
        s.pcm.assign(all.begin() + long(body) + 4, all.end());
        s.ok = !s.pcm.empty();
      }
      break;
    }
    if (std::memcmp(h, "desc", 4) == 0 && len >= 32) {
      const uint64_t rate_bits = Be64(h + 12);
      double rate;
      std::memcpy(&rate, &rate_bits, 8);
      s.rate = rate > 0 ? rate : 22050.0;
      const uint32_t flags = Be32(h + 12 + 12);
      s.channels = Be32(h + 12 + 24);
      s.bits = Be32(h + 12 + 28);
      // The trap in this format. CAF is a big-endian container, and its LPCM
      // flag bit 1 is kCAFLinearPCMFormatFlagIsLittleEndian -- the *opposite*
      // sense to the CoreAudio ASBD flag of the same value, where bit 1 is
      // kAudioFormatFlagIsBigEndian. Reading it the ASBD way inverts every
      // decision: Canabalt's files say 2, which means little-endian, and
      // swapping them anyway turns a jump sound into full-scale white noise.
      // Peak and RMS say which is right without anyone having to listen --
      // real audio here peaks around 3,500 of 32,767, the swap peaks at every
      // sample.
      s.big_endian = (flags & 2u) == 0;
    } else if (std::memcmp(h, "data", 4) == 0 && len >= 4) {
      s.pcm.assign(all.begin() + long(body) + 4,
                   all.begin() + long(body) + long(len));
      s.ok = !s.pcm.empty();
    }
    p = body + size_t(len);
  }
  if (s.bits != 16 || s.channels < 1 || s.channels > 2) s.ok = false;
  return s;
}

// --- the mixer -------------------------------------------------------------

struct Buffer {
  std::vector<int16_t> samples;   // host-endian, interleaved
  uint32_t channels = 1;
  double rate = 22050.0;
};

struct Source {
  uint32_t buffer = 0;
  float gain = 1.0f;
  bool looping = false;
  bool playing = false;
  double pos = 0.0;               // in frames, fractional for resampling
};

std::map<uint32_t, Buffer>& Buffers() {
  static std::map<uint32_t, Buffer> m;
  return m;
}
std::map<uint32_t, Source>& Sources() {
  static std::map<uint32_t, Source> m;
  return m;
}

uint32_t g_next_name = 1;
float g_master = 1.0f;
int g_out_rate = 44100;
bool g_audio_open = false;

// Set once, from ARC_VOLUME, so a test run can be inaudible without touching
// the system mixer. 0 is silence, 1 is the gain the game asked for.
float MasterVolume() {
  static bool read = false;
  static float v = 1.0f;
  if (!read) {
    read = true;
    if (const char* e = std::getenv("ARC_VOLUME")) {
      v = float(std::atof(e));
      if (v < 0.0f) v = 0.0f;
      if (v > 1.0f) v = 1.0f;
    }
  }
  return v;
}

#if defined(ARC_HAVE_SDL2)
SDL_AudioDeviceID g_dev = 0;

// Sum every playing source into the output. Linear position stepping rather
// than a resampler: the sources are 22050 into a 44100 device, so the step is
// exactly 0.5 and there is nothing to be clever about. `ponytail: nearest
// sample, no interpolation -- if a title ever ships audio at a rate that is
// not a neat fraction of the device's, this is where the filter goes.`
void MixInto(void*, Uint8* stream, int len) {
  std::memset(stream, 0, size_t(len));
  int16_t* out = reinterpret_cast<int16_t*>(stream);
  const int frames = len / int(sizeof(int16_t) * 2);
  const float master = g_master;
  if (master <= 0.0f) return;

  for (auto& [id, src] : Sources()) {
    if (!src.playing || !src.buffer) continue;
    auto it = Buffers().find(src.buffer);
    if (it == Buffers().end() || it->second.samples.empty()) {
      src.playing = false;
      continue;
    }
    const Buffer& b = it->second;
    const double step = b.rate / double(g_out_rate);
    const size_t total = b.samples.size() / b.channels;
    const float gain = src.gain * master;
    for (int i = 0; i < frames; ++i) {
      size_t frame = size_t(src.pos);
      if (frame >= total) {
        if (!src.looping) { src.playing = false; break; }
        src.pos -= double(total);
        frame = size_t(src.pos);
        if (frame >= total) { src.playing = false; break; }
      }
      const int16_t l = b.samples[frame * b.channels];
      const int16_t r = b.channels > 1 ? b.samples[frame * b.channels + 1] : l;
      int sl = out[i * 2] + int(float(l) * gain);
      int sr = out[i * 2 + 1] + int(float(r) * gain);
      out[i * 2] = int16_t(std::max(-32768, std::min(32767, sl)));
      out[i * 2 + 1] = int16_t(std::max(-32768, std::min(32767, sr)));
      src.pos += step;
    }
  }
}

void OpenDevice() {
  if (g_audio_open) return;
  g_audio_open = true;
  g_master = MasterVolume();
  if (g_master <= 0.0f) {
    std::printf("audio: silent (ARC_VOLUME=0), still decoding and mixing\n");
    return;
  }
  if (SDL_InitSubSystem(SDL_INIT_AUDIO) != 0) {
    std::printf("audio: no device (%s); the game runs silent\n", SDL_GetError());
    return;
  }
  SDL_AudioSpec want{}, got{};
  want.freq = 44100;
  want.format = AUDIO_S16SYS;
  want.channels = 2;
  want.samples = 1024;
  want.callback = MixInto;
  g_dev = SDL_OpenAudioDevice(nullptr, 0, &want, &got, 0);
  if (!g_dev) {
    std::printf("audio: no device (%s); the game runs silent\n", SDL_GetError());
    return;
  }
  g_out_rate = got.freq;
  SDL_PauseAudioDevice(g_dev, 0);
  std::printf("audio: %d Hz, %d channels, master gain %.2f\n", got.freq,
              got.channels, double(g_master));
}

struct Lock {
  Lock() { if (g_dev) SDL_LockAudioDevice(g_dev); }
  ~Lock() { if (g_dev) SDL_UnlockAudioDevice(g_dev); }
};
#else
void OpenDevice() {
  if (g_audio_open) return;
  g_audio_open = true;
  g_master = MasterVolume();
  std::printf("audio: built without SDL2; the game runs silent\n");
}
struct Lock {};
#endif

// --- AudioFile -------------------------------------------------------------

std::map<uint32_t, Sound>& Files() {
  static std::map<uint32_t, Sound> m;
  return m;
}
uint32_t g_next_file = 1;

// noErr.
uint32_t Ok(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
            uint32_t, uint32_t) {
  return 0;
}

// kAudioFileUnspecifiedError, the one the framework really returns, so a
// caller matching on it behaves as it would.
const uint32_t kFileError = 0x7768743F;

uint32_t FileOpenURL(uint32_t url, uint32_t, uint32_t, uint32_t out,
                     uint32_t, uint32_t, uint32_t, uint32_t) {
  std::string path = GuestStringText(url);
  if (path.rfind("file://", 0) == 0) path = path.substr(7);
  Sound s = ReadCaf(path);
  if (!s.ok) return kFileError;
  const uint32_t id = g_next_file++;
  Files()[id] = std::move(s);
  if (out) ARC_ST32(out, id);
  return 0;
}

// 'dfmt' and 'bcnt'. Anything else is a property this game does not ask for,
// and answering it with a made-up value would be worse than refusing.
const uint32_t kDataFormat = 0x64666D74;      // 'dfmt'
const uint32_t kByteCount = 0x62636E74;       // 'bcnt'

uint32_t FileGetProperty(uint32_t file, uint32_t prop, uint32_t io_size,
                         uint32_t out, uint32_t, uint32_t, uint32_t,
                         uint32_t) {
  auto it = Files().find(file);
  if (it == Files().end() || !out) return kFileError;
  const Sound& s = it->second;
  if (prop == kDataFormat) {
    // AudioStreamBasicDescription, 40 bytes, in the guest's own endianness.
    double rate = s.rate;
    uint32_t w[10] = {0};
    std::memcpy(w, &rate, 8);
    w[2] = 0x6C70636D;                       // 'lpcm'
    w[3] = 4 | 8;                            // signed integer, packed
    w[4] = s.channels * (s.bits / 8);        // bytes per packet
    w[5] = 1;                                // frames per packet
    w[6] = s.channels * (s.bits / 8);        // bytes per frame
    w[7] = s.channels;
    w[8] = s.bits;
    w[9] = 0;
    for (int i = 0; i < 10; ++i) ARC_ST32(out + uint32_t(i * 4), w[i]);
    if (io_size) ARC_ST32(io_size, 40);
    return 0;
  }
  if (prop == kByteCount) {
    const uint64_t n = s.pcm.size();
    ARC_ST32(out, uint32_t(n & 0xFFFFFFFFu));
    ARC_ST32(out + 4, uint32_t(n >> 32));
    if (io_size) ARC_ST32(io_size, 8);
    return 0;
  }
  return kFileError;
}

uint32_t FileReadBytes(uint32_t file, uint32_t, uint32_t start_lo,
                       uint32_t start_hi, uint32_t io_n, uint32_t out,
                       uint32_t, uint32_t) {
  auto it = Files().find(file);
  if (it == Files().end() || !io_n || !out) return kFileError;
  const Sound& s = it->second;
  const uint64_t start = uint64_t(start_hi) << 32 | start_lo;
  if (start >= s.pcm.size()) return kFileError;
  uint32_t want = ARC_LD32(io_n);
  const uint64_t avail = s.pcm.size() - start;
  if (want > avail) want = uint32_t(avail);
  for (uint32_t i = 0; i < want; ++i)
    ARC_ST8(out + i, s.pcm[size_t(start) + i]);
  // The format reported by 'dfmt' says native-endian signed PCM, so the bytes
  // handed back have to be exactly that. CAF stores whichever order the
  // encoder chose -- Canabalt's are big-endian -- and a run of samples with
  // the halves the wrong way round is not quiet or distorted, it is loud
  // white noise, which is a bad thing to discover through a speaker.
  if (s.big_endian && s.bits == 16) {
    for (uint32_t i = 0; i + 1 < want; i += 2) {
      const uint8_t a = uint8_t(ARC_LD8(out + i));
      const uint8_t b = uint8_t(ARC_LD8(out + i + 1));
      ARC_ST8(out + i, b);
      ARC_ST8(out + i + 1, a);
    }
  }
  ARC_ST32(io_n, want);
  return 0;
}

uint32_t FileClose(uint32_t file, uint32_t, uint32_t, uint32_t, uint32_t,
                   uint32_t, uint32_t, uint32_t) {
  Files().erase(file);
  return 0;
}

// --- OpenAL ----------------------------------------------------------------

const uint32_t AL_BUFFER = 0x1009;
const uint32_t AL_LOOPING = 0x1007;
const uint32_t AL_GAIN = 0x100A;
const uint32_t AL_FORMAT_MONO16 = 0x1101;
const uint32_t AL_FORMAT_STEREO16 = 0x1103;

uint32_t GenNames(uint32_t n, uint32_t out, uint32_t, uint32_t, uint32_t,
                  uint32_t, uint32_t, uint32_t) {
  for (uint32_t i = 0; i < n && out; ++i)
    ARC_ST32(out + i * 4, g_next_name++);
  return 0;
}

uint32_t GenSources(uint32_t n, uint32_t out, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  OpenDevice();
  Lock lock;
  for (uint32_t i = 0; i < n && out; ++i) {
    const uint32_t id = g_next_name++;
    Sources()[id] = Source{};
    ARC_ST32(out + i * 4, id);
  }
  return 0;
}

uint32_t DeleteSources(uint32_t n, uint32_t names, uint32_t, uint32_t,
                       uint32_t, uint32_t, uint32_t, uint32_t) {
  Lock lock;
  for (uint32_t i = 0; i < n && names; ++i)
    Sources().erase(ARC_LD32(names + i * 4));
  return 0;
}

uint32_t SourceI(uint32_t sid, uint32_t param, uint32_t value, uint32_t,
                 uint32_t, uint32_t, uint32_t, uint32_t) {
  Lock lock;
  auto it = Sources().find(sid);
  if (it == Sources().end()) return 0;
  if (param == AL_BUFFER) {
    it->second.buffer = value;
    it->second.pos = 0.0;
  } else if (param == AL_LOOPING) {
    it->second.looping = value != 0;
  }
  return 0;
}

uint32_t SourceF(uint32_t sid, uint32_t param, uint32_t bits, uint32_t,
                 uint32_t, uint32_t, uint32_t, uint32_t) {
  Lock lock;
  auto it = Sources().find(sid);
  if (it == Sources().end()) return 0;
  float v;
  std::memcpy(&v, &bits, 4);
  if (param == AL_GAIN) it->second.gain = v < 0.0f ? 0.0f : v;
  return 0;
}

uint32_t SourcePlay(uint32_t sid, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t, uint32_t) {
  Lock lock;
  auto it = Sources().find(sid);
  if (it == Sources().end()) return 0;
  it->second.pos = 0.0;
  it->second.playing = true;
  if (std::getenv("ARC_TRACE_AUDIO"))
    std::printf("[audio] play source %u -> buffer %u, gain %.2f%s\n", sid,
                it->second.buffer, double(it->second.gain),
                it->second.looping ? ", looping" : "");
  return 0;
}

// The extension the whole thing hinges on. `data` is a guest pointer; the
// samples are copied out of it because the guest may free it immediately, and
// the format word says how wide a frame is.
uint32_t BufferDataStatic(uint32_t bid, uint32_t format, uint32_t data,
                          uint32_t size, uint32_t freq, uint32_t, uint32_t,
                          uint32_t) {
  Lock lock;
  Buffer b;
  b.channels = format == AL_FORMAT_STEREO16 ? 2 : 1;
  b.rate = freq ? double(freq) : 22050.0;
  if (format != AL_FORMAT_MONO16 && format != AL_FORMAT_STEREO16) return 0;
  b.samples.resize(size / 2);
  for (size_t i = 0; i < b.samples.size(); ++i)
    b.samples[i] = int16_t(ARC_LD16(data + uint32_t(i * 2)));
  // Peak, not just length. A buffer of the right size full of zeroes is what
  // a wrong offset into the file looks like, and it is indistinguishable from
  // working until someone listens.
  if (std::getenv("ARC_TRACE_AUDIO")) {
    int peak = 0;
    for (int16_t v : b.samples) peak = std::max(peak, std::abs(int(v)));
    std::printf("[audio] buffer %u: %zu frames, %.0f Hz, %u ch, peak %d\n",
                bid, b.samples.size() / b.channels, b.rate, b.channels, peak);
  }
  Buffers()[bid] = std::move(b);
  return 0;
}

uint32_t g_proc_address = 0;

uint32_t GetProcAddress(uint32_t, uint32_t name, uint32_t, uint32_t, uint32_t,
                        uint32_t, uint32_t, uint32_t) {
  std::string s;
  for (uint32_t i = 0; i < 64 && name; ++i) {
    const uint8_t ch = uint8_t(ARC_LD8(name + i));
    if (!ch) break;
    s.push_back(char(ch));
  }
  if (s == "alBufferDataStatic") return g_proc_address;
  return 0;
}

uint32_t True(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
              uint32_t, uint32_t) {
  return 1;
}

// A device and a context have to be non-null or the game concludes there is no
// audio hardware and takes a path with much less exercise on it.
uint32_t OpenHandle(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                    uint32_t, uint32_t) {
  static uint32_t handle = 0x0A0D0000;
  return ++handle;
}

struct Shim {
  const char* name;
  uint32_t (*fn)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                 uint32_t, uint32_t);
};

const Shim kShims[] = {
    // AudioSession is told everything worked, because nothing depends on it.
    {"_AudioSessionInitialize", Ok},
    {"_AudioSessionSetProperty", Ok},
    {"_AudioSessionGetProperty", Ok},
    {"_AudioSessionSetActive", Ok},

    {"_AudioFileOpenURL", FileOpenURL},
    {"_AudioFileGetProperty", FileGetProperty},
    {"_AudioFileReadBytes", FileReadBytes},
    {"_AudioFileClose", FileClose},

    {"_alcOpenDevice", OpenHandle},
    {"_alcCreateContext", OpenHandle},
    {"_alcMakeContextCurrent", True},
    {"_alcDestroyContext", Ok},
    {"_alcCloseDevice", True},
    {"_alcGetProcAddress", GetProcAddress},
    {"_alGetError", Ok},
    {"_alGenBuffers", GenNames},
    {"_alGenSources", GenSources},
    {"_alDeleteSources", DeleteSources},
    {"_alSourcei", SourceI},
    {"_alSourcef", SourceF},
    {"_alSourcePlay", SourcePlay},
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
  // alBufferDataStatic has no import of its own -- it is an extension, fetched
  // by name -- so it needs an address of its own to be called at. Any guest
  // address the dispatcher can reach will do.
  if (!g_proc_address) {
    g_proc_address = arc_guest_alloc(16, 8);
    if (g_proc_address)
      arc_register_native(g_proc_address, "alBufferDataStatic",
                          BufferDataStatic);
  }
  return claimed;
}

}  // namespace arc
