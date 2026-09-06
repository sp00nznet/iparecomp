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

bool LoadPng(const std::string& path, Image* out) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return false;
  png_structp png =
      png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png) {
    std::fclose(f);
    return false;
  }
  png_infop info = png_create_info_struct(png);
  if (!info || setjmp(png_jmpbuf(png))) {
    png_destroy_read_struct(&png, info ? &info : nullptr, nullptr);
    std::fclose(f);
    return false;
  }
  png_init_io(png, f);
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
  std::fclose(f);
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
