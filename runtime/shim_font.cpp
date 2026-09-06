// Fonts, backed by FreeType.
//
// The stub version of this hung the game, and the reason is worth keeping in
// view: text layout is a loop over metrics, so invented metrics do not draw
// the wrong thing, they fail to terminate. `-[SSText(Private)
// nextWrapOffsetForGlyphs:]` asks how many glyphs fit in a line, and a made-up
// advance either fits none or divides by nothing.
//
// So the metrics are real, out of the bundle's own Nokia.ttf. Advances and
// bounding boxes come back in font units, which is what CoreGraphics returns
// and what the caller scales by its own point size.
//
// One thing here is *not* known to be right. A CGGlyph is a glyph index, not a
// character, and this font's indices are nothing like ASCII -- glyph 65 is a
// quotation mark, and `A` is glyph 16. Whatever maps one to the other in the
// game does not go through any imported function, so the values arriving here
// are passed to FreeType as indices and taken at face value. The layout is
// unaffected either way, because this font's advances are nearly uniform; if
// the drawn text turns out to be the wrong letters, this comment is where to
// start.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <ft2build.h>
#include FT_FREETYPE_H

#include "arm32_context.h"
#include "macho_image.h"

namespace arc {

bool BitmapContextInfo(uint32_t handle, uint32_t* data, int* width, int* height,
                       int* stride);
bool BitmapContextTransform(uint32_t handle, float* sx, float* sy, float* tx,
                            float* ty);
std::string BundlePath();

namespace {

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

uint32_t Bits(float f) {
  uint32_t u;
  std::memcpy(&u, &f, 4);
  return u;
}

FT_Library& Library() {
  static FT_Library lib = nullptr;
  static bool tried = false;
  if (!tried) {
    tried = true;
    if (FT_Init_FreeType(&lib)) lib = nullptr;
  }
  return lib;
}

// A data provider is a filename until something asks for the bytes; a font is
// a face. Both are handed out as small opaque numbers because the guest keeps
// them in a 32-bit register.
std::vector<std::string>& Providers() {
  static std::vector<std::string> v;
  return v;
}

std::vector<FT_Face>& Faces() {
  static std::vector<FT_Face> v;
  return v;
}

constexpr uint32_t kProviderBase = 0xF0000000;
constexpr uint32_t kFontBase = 0xF1000000;

FT_Face FaceOf(uint32_t handle) {
  const uint32_t i = handle - kFontBase;
  return i < Faces().size() ? Faces()[i] : nullptr;
}

void DataProviderCreateWithFilename(Arm32Ctx* c) {
  const uint32_t p = ARC_R(c, 0);
  const char* path = p ? reinterpret_cast<const char*>(uintptr_t(p)) : nullptr;
  if (!path) {
    ARC_W(c, 0, 0);
    return;
  }
  Providers().push_back(path);
  ARC_W(c, 0, kProviderBase + uint32_t(Providers().size() - 1));
}

void FontCreateWithDataProvider(Arm32Ctx* c) {
  const uint32_t i = ARC_R(c, 0) - kProviderBase;
  if (!Library() || i >= Providers().size()) {
    ARC_W(c, 0, 0);
    return;
  }
  // The path the guest gives is relative to the bundle it thinks it is in.
  std::string path = Providers()[i];
  FT_Face face = nullptr;
  if (FT_New_Face(Library(), path.c_str(), 0, &face)) {
    const std::string alt = BundlePath() + "/" + path;
    if (FT_New_Face(Library(), alt.c_str(), 0, &face)) {
      std::printf("font: could not open %s\n", path.c_str());
      ARC_W(c, 0, 0);
      return;
    }
  }
  Faces().push_back(face);
  std::printf("font: %s, %ld glyphs, %d units/em\n",
              face->family_name ? face->family_name : path.c_str(),
              long(face->num_glyphs), int(face->units_per_EM));
  ARC_W(c, 0, kFontBase + uint32_t(Faces().size() - 1));
}

void Retain(Arm32Ctx* c) { ARC_W(c, 0, ARC_R(c, 0)); }
void ReleaseNothing(Arm32Ctx* c) { ARC_W(c, 0, 0); }

void UnitsPerEm(Arm32Ctx* c) {
  FT_Face f = FaceOf(ARC_R(c, 0));
  ARC_W(c, 0, f ? uint32_t(f->units_per_EM) : 2048);
}

void CapHeight(Arm32Ctx* c) {
  FT_Face f = FaceOf(ARC_R(c, 0));
  if (!f) {
    ARC_W(c, 0, 1434);
    return;
  }
  // No OS/2 cap height in every font, and the ascender is the value text
  // layout actually wants when there is none.
  ARC_W(c, 0, uint32_t(f->ascender));
}

// CGFontGetGlyphAdvances(font, glyphs, count, advances) -- glyphs are 16-bit,
// advances are ints, both in font units.
void GlyphAdvances(Arm32Ctx* c) {
  FT_Face f = FaceOf(A(c, 0));
  const uint32_t glyphs = A(c, 1), count = A(c, 2), out = A(c, 3);
  if (!out) {
    ARC_W(c, 0, 0);
    return;
  }
  for (uint32_t i = 0; i < count && i < 8192; ++i) {
    int32_t advance = 0;
    if (f && glyphs) {
      const uint16_t g = ARC_LD16(glyphs + i * 2);
      if (!FT_Load_Glyph(f, g, FT_LOAD_NO_SCALE))
        advance = int32_t(f->glyph->metrics.horiAdvance);
    }
    ARC_ST32(out + i * 4, uint32_t(advance));
  }
  ARC_W(c, 0, 1);
}

// CGFontGetGlyphBBoxes(font, glyphs, count, bboxes) -- CGRect each, four
// floats, in font units.
void GlyphBBoxes(Arm32Ctx* c) {
  FT_Face f = FaceOf(A(c, 0));
  const uint32_t glyphs = A(c, 1), count = A(c, 2), out = A(c, 3);
  if (!out) {
    ARC_W(c, 0, 0);
    return;
  }
  for (uint32_t i = 0; i < count && i < 8192; ++i) {
    float x = 0, y = 0, w = 0, h = 0;
    if (f && glyphs) {
      const uint16_t g = ARC_LD16(glyphs + i * 2);
      if (!FT_Load_Glyph(f, g, FT_LOAD_NO_SCALE)) {
        const FT_Glyph_Metrics& m = f->glyph->metrics;
        x = float(m.horiBearingX);
        y = float(m.horiBearingY - m.height);
        w = float(m.width);
        h = float(m.height);
      }
    }
    const uint32_t at = out + i * 16;
    ARC_ST32(at + 0, Bits(x));
    ARC_ST32(at + 4, Bits(y));
    ARC_ST32(at + 8, Bits(w));
    ARC_ST32(at + 12, Bits(h));
  }
  ARC_W(c, 0, 1);
}

// --- drawing ---------------------------------------------------------------

uint32_t g_current_font = 0;
float g_font_size = 12.0f;

void ContextSetFont(Arm32Ctx* c) { g_current_font = ARC_R(c, 1); }
void ContextSetFontSize(Arm32Ctx* c) {
  const float s = Af(c, 1);
  if (s > 0) g_font_size = s;
}

// CGContextShowGlyphsAtPoint(context, x, y, glyphs, count). Rasterises into
// whatever bitmap context is current -- which is the buffer the game is about
// to hand to glTexImage2D, so this is where text becomes a texture.
void ShowGlyphsAtPoint(Arm32Ctx* c) {
  const bool trace = std::getenv("ARC_TRACE_TEX") != nullptr;
  uint32_t data = 0;
  int bw = 0, bh = 0, stride = 0;
  if (!BitmapContextInfo(A(c, 0), &data, &bw, &bh, &stride)) {
    if (trace) std::printf("[glyph] no bitmap context %#x\n", A(c, 0));
    return;
  }
  FT_Face f = FaceOf(g_current_font);
  if (!f) {
    if (trace) std::printf("[glyph] no face for font %#x\n", g_current_font);
    return;
  }
  // ARC_TRACE_TEX=1 also covers this: where the pen was put, how big the
  // bitmap is, and -- below -- how much of the text actually landed inside it.
  // Text that misses its own texture is indistinguishable from text that was
  // never drawn, right up until the count says which.
  if (trace)
    std::printf("[glyph] ctx=%#x data=%#x %dx%d stride=%d pen=(%.1f,%.1f) "
                "n=%u size=%.1f\n",
                A(c, 0), data, bw, bh, stride, Af(c, 1), Af(c, 2), A(c, 4),
                double(g_font_size));

  // Through the context's transform: the guest lays text out top-down and
  // flips the context to suit, so the point it names is not where the glyph
  // goes until that flip is applied.
  float sx = 1, sy = 1, tx = 0, ty = 0;
  BitmapContextTransform(A(c, 0), &sx, &sy, &tx, &ty);
  const float px = tx + sx * Af(c, 1), py = ty + sy * Af(c, 2);
  const uint32_t glyphs = A(c, 3), count = A(c, 4);
  if (!glyphs) return;
  FT_Set_Pixel_Sizes(f, 0, FT_UInt(g_font_size > 1 ? g_font_size : 12));

  // What the text actually says. A CGGlyph is an index, so the log is
  // unreadable without turning it back into characters -- and "the buttons
  // are illegible" is a different bug from "the buttons say the wrong thing".
  if (trace) {
    std::string text;
    for (uint32_t i = 0; i < count && i < 128; ++i) {
      const uint16_t g = ARC_LD16(glyphs + i * 2);
      char ch = '?';
      for (int k = 32; k < 127; ++k)
        if (FT_Get_Char_Index(f, FT_ULong(k)) == g) {
          ch = char(k);
          break;
        }
      text += ch;
    }
    std::printf("  text \"%s\"\n", text.c_str());
  }

  float pen = px;
  int lit = 0, lost = 0;
  uint8_t* dst = reinterpret_cast<uint8_t*>(uintptr_t(data));
  for (uint32_t i = 0; i < count && i < 4096; ++i) {
    const uint16_t g = ARC_LD16(glyphs + i * 2);
    if (FT_Load_Glyph(f, g, FT_LOAD_RENDER)) continue;
    const FT_GlyphSlot slot = f->glyph;
    const FT_Bitmap& bm = slot->bitmap;
    for (unsigned row = 0; row < bm.rows; ++row) {
      // CoreGraphics has the origin at the bottom left; the glyph bitmap runs
      // top down. Same flip as every other blit here.
      const int dy = bh - 1 - int(py + float(slot->bitmap_top) - float(row));
      if (dy < 0 || dy >= bh) {
        lost += int(bm.width);
        continue;
      }
      for (unsigned col = 0; col < bm.width; ++col) {
        const int dx = int(pen) + slot->bitmap_left + int(col);
        if (dx < 0 || dx >= bw) {
          ++lost;
          continue;
        }
        const uint8_t a = bm.buffer[row * unsigned(bm.pitch) + col];
        if (!a) continue;
        // White text, coverage in alpha. The game tints it afterwards.
        uint8_t* p = dst + size_t(dy) * size_t(stride) + size_t(dx) * 4;
        p[0] = 0xFF;
        p[1] = 0xFF;
        p[2] = 0xFF;
        p[3] = a;
        ++lit;
      }
    }
    pen += float(slot->advance.x) / 64.0f;
  }
  if (trace) std::printf("  %d pixels landed, %d fell outside\n", lit, lost);
}

struct Shim {
  const char* name;
  ArcCtxFn fn;
};

const Shim kShims[] = {
    {"_CGDataProviderCreateWithFilename", DataProviderCreateWithFilename},
    {"_CGDataProviderRelease", ReleaseNothing},
    {"_CGFontCreateWithDataProvider", FontCreateWithDataProvider},
    {"_CGFontRetain", Retain},
    {"_CGFontRelease", ReleaseNothing},
    {"_CGFontGetUnitsPerEm", UnitsPerEm},
    {"_CGFontGetCapHeight", CapHeight},
    {"_CGFontGetGlyphAdvances", GlyphAdvances},
    {"_CGFontGetGlyphBBoxes", GlyphBBoxes},
    {"_CGContextSetFont", ContextSetFont},
    {"_CGContextSetFontSize", ContextSetFontSize},
    {"_CGContextShowGlyphsAtPoint", ShowGlyphsAtPoint},
};

}  // namespace

size_t InstallFontShims(const MachOImage& img) {
  size_t claimed = 0;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    for (const auto& s : kShims)
      if (im.name == s.name) {
        arc_register_ctx_native(im.stub, s.name, s.fn);
        ++claimed;
      }
  }
  return claimed;
}

}  // namespace arc
