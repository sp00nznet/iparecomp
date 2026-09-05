// CoreGraphics geometry.
//
// These are the one part of the framework surface that can be reproduced
// exactly rather than approximated: they are pure functions over rectangles
// and points, documented down to the edge cases, with no state and no drawing.
// So they are written out properly -- an "empty rect is never equal to
// anything" or an inset that forgets to normalise would be a wrong answer, not
// a missing feature, and wrong answers in geometry surface as things drawn in
// the wrong place much later.
//
// The awkwardness is the same one as everywhere else: a CGRect is four floats
// passed in four argument words, and returned through a hidden pointer because
// it does not fit in a register.
#include <cmath>
#include <cstring>

#include "arm32_context.h"
#include "macho_image.h"

namespace arc {
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

struct Rect {
  float x, y, w, h;
};

Rect ReadRect(Arm32Ctx* c, int at) {
  return {Af(c, at), Af(c, at + 1), Af(c, at + 2), Af(c, at + 3)};
}

// A rectangle with negative width or height describes the same region as its
// normalised form, and every CoreGraphics predicate compares the normalised
// one. Skipping this is the classic way these come out subtly wrong.
Rect Standardize(Rect r) {
  if (r.w < 0) {
    r.x += r.w;
    r.w = -r.w;
  }
  if (r.h < 0) {
    r.y += r.h;
    r.h = -r.h;
  }
  return r;
}

bool IsEmpty(const Rect& r) {
  return !(r.w > 0) || !(r.h > 0) || r.w != r.w || r.h != r.h;
}

void ReturnRect(Arm32Ctx* c, const Rect& r) {
  const uint32_t out = ARC_R(c, 0);
  if (!out) return;
  ARC_ST32(out + 0, Bits(r.x));
  ARC_ST32(out + 4, Bits(r.y));
  ARC_ST32(out + 8, Bits(r.w));
  ARC_ST32(out + 12, Bits(r.h));
}

void RectEqualToRect(Arm32Ctx* c) {
  const Rect a = Standardize(ReadRect(c, 0));
  const Rect b = Standardize(ReadRect(c, 4));
  // Two empty rectangles are equal whatever their origins, which is the
  // documented behaviour and not what a field-by-field compare would say.
  if (IsEmpty(a) && IsEmpty(b)) {
    ARC_W(c, 0, 1);
    return;
  }
  const bool same = a.x == b.x && a.y == b.y && a.w == b.w && a.h == b.h;
  ARC_W(c, 0, same ? 1 : 0);
}

void RectContainsPoint(Arm32Ctx* c) {
  const Rect r = Standardize(ReadRect(c, 0));
  const float px = Af(c, 4), py = Af(c, 5);
  // Half-open: the near edges are inside and the far ones are not, so
  // adjacent rectangles do not both claim a point.
  const bool in = !IsEmpty(r) && px >= r.x && px < r.x + r.w && py >= r.y &&
                  py < r.y + r.h;
  ARC_W(c, 0, in ? 1 : 0);
}

void RectInset(Arm32Ctx* c) {
  // Struct return: the hidden pointer is r0, so the rectangle starts at r1.
  const Rect in = Standardize(
      {Af(c, 1), Af(c, 2), Af(c, 3), Af(c, 4)});
  const float dx = Af(c, 5), dy = Af(c, 6);
  Rect r{in.x + dx, in.y + dy, in.w - 2 * dx, in.h - 2 * dy};
  // Insetting past the middle gives the null rectangle rather than a negative
  // one.
  if (r.w < 0 || r.h < 0) r = {0, 0, 0, 0};
  ReturnRect(c, r);
}

// An affine transform is six floats: a b c d tx ty.
struct Affine {
  float a, b, c, d, tx, ty;
};

Affine ReadAffine(Arm32Ctx* c, int at) {
  return {Af(c, at),     Af(c, at + 1), Af(c, at + 2),
          Af(c, at + 3), Af(c, at + 4), Af(c, at + 5)};
}

void AffineIsIdentity(Arm32Ctx* c) {
  const Affine t = ReadAffine(c, 0);
  const bool id = t.a == 1 && t.b == 0 && t.c == 0 && t.d == 1 && t.tx == 0 &&
                  t.ty == 0;
  ARC_W(c, 0, id ? 1 : 0);
}

void AffineTranslate(Arm32Ctx* c) {
  const uint32_t out = ARC_R(c, 0);
  const Affine t = ReadAffine(c, 1);
  const float tx = Af(c, 7), ty = Af(c, 8);
  if (!out) return;
  const float values[6] = {t.a,
                           t.b,
                           t.c,
                           t.d,
                           t.tx + tx * t.a + ty * t.c,
                           t.ty + tx * t.b + ty * t.d};
  for (int i = 0; i < 6; ++i) ARC_ST32(out + uint32_t(i) * 4, Bits(values[i]));
}

struct Shim {
  const char* name;
  ArcCtxFn fn;
};

const Shim kShims[] = {
    {"_CGRectEqualToRect", RectEqualToRect},
    {"_CGRectContainsPoint", RectContainsPoint},
    {"_CGRectInset", RectInset},
    {"_CGAffineTransformIsIdentity", AffineIsIdentity},
    {"_CGAffineTransformTranslate", AffineTranslate},
};

}  // namespace

size_t InstallCoreGraphicsShims(const MachOImage& img) {
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
