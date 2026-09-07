// Images: loading a PNG out of the bundle, and the bitmap context the game
// composes textures in before handing them to GL.
//
// This is the shape of it on a device. `+[UIImage imageNamed:]` decodes a file
// from the bundle; `CGBitmapContextCreate` wraps a buffer the app allocated;
// `CGContextDrawImage` scales the image into that buffer; and the buffer goes
// to `glTexImage2D`. Every one of those is a real operation with an observable
// result, so none of them can be stubbed -- a nil image or an untouched buffer
// gives a running game with nothing on screen, which is the least informative
// possible failure.
//
// The decode is libpng rather than anything written here. It was already
// installed, it is the reference implementation, and image decoding is the
// last place to be inventive.
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <png.h>
#include <zlib.h>

#include "arc_mem.h"
#include "arm32_context.h"
#include "macho_image.h"
#include "objc_host.h"
#include "objc_runtime.h"

namespace arc {

std::string BundlePath();
std::string GuestStringText(uint32_t obj);

namespace {

struct Image {
  int width = 0, height = 0;
  std::vector<uint8_t> rgba;  // straight RGBA8, top row first
};

std::map<uint32_t, Image>& Images() {
  static std::map<uint32_t, Image> m;
  return m;
}

// A CGBitmapContext is a buffer the guest owns plus the shape of it. Nothing
// here allocates the pixels: the game did, and it is going to hand the same
// pointer to glTexImage2D afterwards.
struct BitmapContext {
  uint32_t data = 0;
  int width = 0, height = 0;
  int bytes_per_row = 0;
  // The current transform, translate and scale only, which is all any of this
  // is asked for. A point drawn at (x, y) lands at (tx + sx*x, ty + sy*y),
  // still in CoreGraphics' bottom-left space.
  float sx = 1, sy = 1, tx = 0, ty = 0;
};

std::map<uint32_t, BitmapContext>& Contexts() {
  static std::map<uint32_t, BitmapContext> m;
  return m;
}

uint32_t A(Arm32Ctx* c, int i) {
  if (i < 4) return ARC_R(c, uint32_t(i));
  return ARC_LD32(ARC_SP(c) + uint32_t(i - 4) * 4);
}

float Af(Arm32Ctx* c, int i) {
  const uint32_t bits = A(c, i);
  float f;
  std::memcpy(&f, &bits, 4);
  return f;
}

// --- Apple's CgBI PNGs ------------------------------------------------------
//
// A PNG inside a shipped .ipa may have been through Xcode's "compress PNG
// files" step, which does not produce a PNG. It produces a variant with a
// private `CgBI` chunk marked critical, so a conforming decoder must refuse
// it -- libpng says `CgBI: unhandled critical chunk` and stops. Three things
// differ, and all three have to be undone:
//
//   1. the `CgBI` chunk, which is simply dropped;
//   2. the IDAT stream is raw DEFLATE with no zlib header or Adler-32, so it
//      needs inflating with negative window bits and re-wrapping;
//   3. the pixels are BGRA with premultiplied alpha, not RGBA straight.
//
// Only 7 of Canabalt's 73 files are like this, and they are all gameplay art
// -- block, slope, hud, gameover -- so the menu loads without any of this and
// the game does not.
bool IsCgBI(const std::vector<uint8_t>& f) {
  return f.size() > 16 && std::memcmp(f.data() + 12, "CgBI", 4) == 0;
}

uint32_t Be32At(const uint8_t* p) {
  return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}

void PutBe32(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back(uint8_t(x >> 24));
  v.push_back(uint8_t(x >> 16));
  v.push_back(uint8_t(x >> 8));
  v.push_back(uint8_t(x));
}

void PutChunk(std::vector<uint8_t>& out, const char* type,
              const uint8_t* data, size_t n) {
  PutBe32(out, uint32_t(n));
  const size_t crc_from = out.size();
  out.insert(out.end(), type, type + 4);
  out.insert(out.end(), data, data + n);
  const uLong crc = crc32(0, out.data() + crc_from, uInt(4 + n));
  PutBe32(out, uint32_t(crc));
}

// Rebuild a standard PNG from a CgBI one, so libpng does the unfiltering --
// which is the part worth not reimplementing.
bool RepackCgBI(const std::vector<uint8_t>& in, std::vector<uint8_t>* out) {
  std::vector<uint8_t> idat;
  std::vector<uint8_t> head;   // IHDR and anything else worth keeping
  size_t p = 8;
  bool have_ihdr = false;
  while (p + 12 <= in.size()) {
    const uint32_t len = Be32At(in.data() + p);
    const char* type = reinterpret_cast<const char*>(in.data() + p + 4);
    if (p + 12 + len > in.size()) break;
    const uint8_t* body = in.data() + p + 8;
    if (std::memcmp(type, "IHDR", 4) == 0) {
      head.assign(body, body + len);
      have_ihdr = true;
    } else if (std::memcmp(type, "IDAT", 4) == 0) {
      idat.insert(idat.end(), body, body + len);
    } else if (std::memcmp(type, "IEND", 4) == 0) {
      break;
    }
    p += 12 + len;
  }
  if (!have_ihdr || idat.empty() || head.size() < 13) return false;

  // Raw DEFLATE in, so negative window bits. A conforming stream would have a
  // two-byte zlib header this one does not carry.
  std::vector<uint8_t> raw;
  z_stream zs{};
  if (inflateInit2(&zs, -15) != Z_OK) return false;
  zs.next_in = const_cast<Bytef*>(idat.data());
  zs.avail_in = uInt(idat.size());
  std::vector<uint8_t> chunk(65536);
  int rc = Z_OK;
  do {
    zs.next_out = chunk.data();
    zs.avail_out = uInt(chunk.size());
    rc = inflate(&zs, Z_NO_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) break;
    raw.insert(raw.end(), chunk.data(), chunk.data() + (chunk.size() - zs.avail_out));
  } while (rc == Z_OK && zs.avail_in);
  inflateEnd(&zs);
  if (raw.empty()) return false;

  uLongf bound = compressBound(uLong(raw.size()));
  std::vector<uint8_t> packed(bound);
  if (compress2(packed.data(), &bound, raw.data(), uLong(raw.size()), 6) != Z_OK)
    return false;
  packed.resize(bound);

  out->assign(in.begin(), in.begin() + 8);          // the signature
  PutChunk(*out, "IHDR", head.data(), head.size());
  PutChunk(*out, "IDAT", packed.data(), packed.size());
  PutChunk(*out, "IEND", nullptr, 0);
  return true;
}

struct MemRead { const uint8_t* p; size_t left; };

void ReadFromMemory(png_structp png, png_bytep out, png_size_t n) {
  MemRead* m = static_cast<MemRead*>(png_get_io_ptr(png));
  const size_t take = n < m->left ? size_t(n) : m->left;
  std::memcpy(out, m->p, take);
  m->p += take;
  m->left -= take;
}

bool LoadPng(const std::string& path, Image* out) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return false;
  std::vector<uint8_t> file;
  {
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n > 0) {
      file.resize(size_t(n));
      if (std::fread(file.data(), 1, file.size(), f) != file.size())
        file.clear();
    }
  }
  std::fclose(f);
  if (file.size() < 16) return false;

  const bool cgbi = IsCgBI(file);
  std::vector<uint8_t> repacked;
  if (cgbi) {
    if (!RepackCgBI(file, &repacked)) {
      std::printf("image: %s is CgBI and would not repack\n", path.c_str());
      return false;
    }
    file.swap(repacked);
  }

  png_structp png =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png) return false;
  png_infop info = png_create_info_struct(png);
  if (!info || setjmp(png_jmpbuf(png))) {
    png_destroy_read_struct(&png, info ? &info : nullptr, nullptr);
    return false;
  }
  MemRead src{file.data(), file.size()};
  png_set_read_fn(png, &src, ReadFromMemory);
  png_read_info(png, info);

  // Normalise everything to 8-bit RGBA, which is what GL is going to be given
  // and what saves the caller from caring what the file happened to be.
  const png_byte colour = png_get_color_type(png, info);
  const png_byte depth = png_get_bit_depth(png, info);
  if (depth == 16) png_set_strip_16(png);
  if (colour == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
  if (colour == PNG_COLOR_TYPE_GRAY && depth < 8) png_set_expand_gray_1_2_4_to_8(png);
  if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
  if (colour == PNG_COLOR_TYPE_RGB || colour == PNG_COLOR_TYPE_GRAY ||
      colour == PNG_COLOR_TYPE_PALETTE)
    png_set_filler(png, 0xFF, PNG_FILLER_AFTER);
  if (colour == PNG_COLOR_TYPE_GRAY || colour == PNG_COLOR_TYPE_GRAY_ALPHA)
    png_set_gray_to_rgb(png);
  png_read_update_info(png, info);

  out->width = int(png_get_image_width(png, info));
  out->height = int(png_get_image_height(png, info));
  out->rgba.assign(size_t(out->width) * size_t(out->height) * 4, 0);
  std::vector<png_bytep> rows(size_t(out->height));
  for (int y = 0; y < out->height; ++y)
    rows[size_t(y)] = out->rgba.data() + size_t(y) * size_t(out->width) * 4;
  png_read_image(png, rows.data());
  png_destroy_read_struct(&png, &info, nullptr);

  // The two remaining differences, and they are per-pixel: the channels are
  // BGRA rather than RGBA, and the colour is premultiplied by the alpha.
  // Undoing the multiply is what makes an edge pixel the colour it was
  // painted rather than a darker version of it, and skipping it leaves every
  // sprite with a dark halo that looks like bad art rather than a bug.
  if (cgbi) {
    for (size_t i = 0; i + 3 < out->rgba.size(); i += 4) {
      std::swap(out->rgba[i], out->rgba[i + 2]);
      const uint8_t a = out->rgba[i + 3];
      if (a && a != 0xFF) {
        for (int k = 0; k < 3; ++k) {
          const unsigned v = (unsigned(out->rgba[i + k]) * 255u + a / 2) / a;
          out->rgba[i + k] = uint8_t(v > 255u ? 255u : v);
        }
      }
    }
  }
  return true;
}

// +[UIImage imageNamed:] -- the bundle, then the bundle with .png appended,
// which is what the real one does and what the game relies on.
void ImageNamed(Arm32Ctx* c) {
  const std::string name = GuestStringText(ARC_R(c, 2));
  if (name.empty()) {
    ARC_W(c, 0, 0);
    return;
  }
  Image img;
  const std::string base = BundlePath();
  if (!LoadPng(base + "/" + name, &img) &&
      !LoadPng(base + "/" + name + ".png", &img)) {
    std::printf("image: no such file in the bundle: %s\n", name.c_str());
    ARC_W(c, 0, 0);
    return;
  }
  const uint32_t obj = HostAllocInstance(HostClass("UIImage", "NSObject"));
  if (!obj) {
    ARC_W(c, 0, 0);
    return;
  }
  Images()[obj] = std::move(img);
  ARC_W(c, 0, obj);
}

void ImageSize(Arm32Ctx* c) {
  // -[UIImage size] is a CGSize: two floats, returned through the hidden
  // pointer like every other aggregate.
  if (!SendingStret()) {
    arc_trap(c, "-[UIImage size] was reached through the ordinary "
                "objc_msgSend; writing the result would land on the receiver");
    return;
  }
  const uint32_t out = ARC_R(c, 0);
  auto it = Images().find(ARC_R(c, 1));
  const float w = it == Images().end() ? 0.0f : float(it->second.width);
  const float h = it == Images().end() ? 0.0f : float(it->second.height);
  if (!out) return;
  uint32_t bits;
  std::memcpy(&bits, &w, 4);
  ARC_ST32(out + 0, bits);
  std::memcpy(&bits, &h, 4);
  ARC_ST32(out + 4, bits);
}

// A UIImage's CGImage is the same object here: there is one representation and
// nothing distinguishes them.
void CGImageOf(Arm32Ctx*) {}

void ImageWidth(Arm32Ctx* c) {
  auto it = Images().find(ARC_R(c, 0));
  ARC_W(c, 0, it == Images().end() ? 0 : uint32_t(it->second.width));
}

void ImageHeight(Arm32Ctx* c) {
  auto it = Images().find(ARC_R(c, 0));
  ARC_W(c, 0, it == Images().end() ? 0 : uint32_t(it->second.height));
}

// CGBitmapContextCreate(data, width, height, bitsPerComponent, bytesPerRow,
//                       colorspace, bitmapInfo)
void BitmapContextCreate(Arm32Ctx* c) {
  BitmapContext ctx;
  ctx.data = A(c, 0);
  ctx.width = int(A(c, 1));
  ctx.height = int(A(c, 2));
  ctx.bytes_per_row = int(A(c, 4));
  if (!ctx.bytes_per_row) ctx.bytes_per_row = ctx.width * 4;
  if (!ctx.data || ctx.width <= 0 || ctx.height <= 0) {
    ARC_W(c, 0, 0);
    return;
  }
  const uint32_t obj =
      HostAllocInstance(HostClass("CGBitmapContext", "NSObject"));
  if (obj) Contexts()[obj] = ctx;
  ARC_W(c, 0, obj);
}

// CGContextDrawImage(context, rect, image). The rect is four floats, so the
// arguments run r1..r3 and then the stack, with the image last.
void ContextDrawImage(Arm32Ctx* c) {
  auto ctx = Contexts().find(A(c, 0));
  if (ctx == Contexts().end()) return;
  const float rx = Af(c, 1), ry = Af(c, 2), rw = Af(c, 3), rh = Af(c, 4);
  auto img = Images().find(A(c, 5));
  if (img == Images().end() || rw <= 0 || rh <= 0) return;

  const BitmapContext& b = ctx->second;
  const Image& src = img->second;
  uint8_t* dst = reinterpret_cast<uint8_t*>(uintptr_t(b.data));

  // Nearest-neighbour, and vertically flipped: CoreGraphics puts the origin at
  // the bottom left and the decoded rows start at the top. Getting that
  // backwards gives an upside-down game rather than an error.
  const int x0 = int(rx), y0 = int(ry);
  const int w = int(rw), h = int(rh);
  for (int y = 0; y < h; ++y) {
    const int dy = b.height - 1 - (y0 + y);
    if (dy < 0 || dy >= b.height) continue;
    const int sy = src.height - 1 - (y * src.height / h);
    for (int x = 0; x < w; ++x) {
      const int dx = x0 + x;
      if (dx < 0 || dx >= b.width) continue;
      const int sx = x * src.width / w;
      if (sx < 0 || sx >= src.width || sy < 0 || sy >= src.height) continue;
      const uint8_t* s =
          src.rgba.data() + (size_t(sy) * size_t(src.width) + size_t(sx)) * 4;
      uint8_t* d = dst + size_t(dy) * size_t(b.bytes_per_row) + size_t(dx) * 4;
      std::memcpy(d, s, 4);
    }
  }
}

// UIGraphics keeps a stack of contexts so that drawing code can ask for "the
// current one" rather than being handed it. Text rasterisation pushes the
// bitmap context it made and then draws through this.
std::vector<uint32_t>& ContextStack() {
  static std::vector<uint32_t> s;
  return s;
}

void GraphicsPushContext(Arm32Ctx* c) { ContextStack().push_back(ARC_R(c, 0)); }
void GraphicsPopContext(Arm32Ctx*) {
  if (!ContextStack().empty()) ContextStack().pop_back();
}
void GraphicsGetCurrentContext(Arm32Ctx* c) {
  ARC_W(c, 0, ContextStack().empty() ? 0 : ContextStack().back());
}

void ReturnOne(Arm32Ctx* c) { ARC_W(c, 0, 1); }
void ReturnZero(Arm32Ctx* c) { ARC_W(c, 0, 0); }

struct CShim {
  const char* name;
  ArcCtxFn fn;
};

const CShim kCImports[] = {
    {"_CGBitmapContextCreate", BitmapContextCreate},
    {"_CGContextDrawImage", ContextDrawImage},
    {"_CGImageGetWidth", ImageWidth},
    {"_CGImageGetHeight", ImageHeight},
    // A colour space is a token here: one representation, nothing to choose.
    {"_CGColorSpaceCreateDeviceRGB", ReturnOne},
    {"_CGColorSpaceRelease", ReturnZero},
    {"_CGContextRelease", ReturnZero},
    {"_CGColorRetain", ReturnZero},
    {"_CGColorRelease", ReturnZero},
    {"_UIGraphicsPushContext", GraphicsPushContext},
    {"_UIGraphicsPopContext", GraphicsPopContext},
    {"_UIGraphicsGetCurrentContext", GraphicsGetCurrentContext},
};

struct ObjcShim {
  const char* cls;
  bool meta;
  const char* sel;
  ArcCtxFn fn;
};

const ObjcShim kObjc[] = {
    {"UIImage", true, "imageNamed:", ImageNamed},
    {"UIImage", false, "size", ImageSize},
    {"UIImage", false, "CGImage", CGImageOf},
};

}  // namespace

// The context's transform, for whoever draws into it. Ignoring this put every
// glyph ten rows too high: Canabalt sets up `translate(0, 2);
// translate(0, 30); scale(1, -1)` so it can lay text out top-down, and text
// drawn at y=21 in that space belongs at y=11 from the bottom, not 21. The
// tops of the letters fell outside the bitmap, and ABOUT came out as HDOUC.
bool BitmapContextTransform(uint32_t handle, float* sx, float* sy, float* tx,
                            float* ty) {
  auto it = Contexts().find(handle);
  if (it == Contexts().end()) return false;
  if (sx) *sx = it->second.sx;
  if (sy) *sy = it->second.sy;
  if (tx) *tx = it->second.tx;
  if (ty) *ty = it->second.ty;
  return true;
}

// CGContextTranslateCTM(c, dx, dy) displaces the origin, so a later point goes
// through the old transform *after* the displacement: the translation moves by
// the current scale, and the scale is unchanged.
void BitmapContextTranslate(uint32_t handle, float dx, float dy) {
  auto it = Contexts().find(handle);
  if (it == Contexts().end()) return;
  it->second.tx += it->second.sx * dx;
  it->second.ty += it->second.sy * dy;
}

void BitmapContextScale(uint32_t handle, float kx, float ky) {
  auto it = Contexts().find(handle);
  if (it == Contexts().end()) return;
  it->second.sx *= kx;
  it->second.sy *= ky;
}

// The bitmap context, for whoever else draws into it -- the font shims
// rasterise glyphs straight into the same buffer the game is about to upload.
bool BitmapContextInfo(uint32_t handle, uint32_t* data, int* width, int* height,
                       int* stride) {
  auto it = Contexts().find(handle);
  if (it == Contexts().end()) return false;
  if (data) *data = it->second.data;
  if (width) *width = it->second.width;
  if (height) *height = it->second.height;
  if (stride) *stride = it->second.bytes_per_row;
  return true;
}

size_t InstallImageShims(const MachOImage& img) {
  for (const auto& e : kObjc) {
    HostClass(e.cls, "NSObject");
    HostMethod(e.cls, e.meta, e.sel, e.fn);
  }
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const auto& s : kCImports)
      if (im.name == s.name) {
        arc_register_ctx_native(im.stub, s.name, s.fn);
        ++claimed;
      }
  }
  return claimed;
}

}  // namespace arc
