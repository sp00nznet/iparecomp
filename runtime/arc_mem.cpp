#include "arc_mem.h"

#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace {

// Where the guest's world sits. The image is at its link address, 0x1000 to
// about 0x67000, so these start well clear of it and of each other.
constexpr uint32_t kHeapBase = 0x10000000u;
constexpr uint32_t kHeapSize = 0x20000000u;  // 512 MB of address space
constexpr uint32_t kStackBase = 0x40000000u;
constexpr uint32_t kStackSize = 0x00800000u;  // 8 MB

// Pages are committed as the bump pointer reaches them, so reserving half a
// gigabyte costs address space and nothing else.
constexpr uint32_t kChunk = 0x100000u;  // 1 MB

uint32_t g_next = kHeapBase;
uint32_t g_committed = kHeapBase;
bool g_ready = false;

bool Reserve(uint32_t at, uint32_t size) {
#if defined(_WIN32)
  return VirtualAlloc(reinterpret_cast<LPVOID>(uintptr_t(at)), size,
                      MEM_RESERVE, PAGE_NOACCESS) ==
         reinterpret_cast<LPVOID>(uintptr_t(at));
#else
  void* p = mmap(reinterpret_cast<void*>(uintptr_t(at)), size, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
  return p == reinterpret_cast<void*>(uintptr_t(at));
#endif
}

bool Commit(uint32_t at, uint32_t size) {
#if defined(_WIN32)
  return VirtualAlloc(reinterpret_cast<LPVOID>(uintptr_t(at)), size,
                      MEM_COMMIT, PAGE_READWRITE) != nullptr;
#else
  return mprotect(reinterpret_cast<void*>(uintptr_t(at)), size,
                  PROT_READ | PROT_WRITE) == 0;
#endif
}

}  // namespace

int arc_mem_init(void) {
  if (g_ready) return 1;
  if (!Reserve(kHeapBase, kHeapSize)) return 0;
  if (!Reserve(kStackBase, kStackSize)) return 0;
  // The stack is committed whole: it is small, and a stack that faults part of
  // the way down is far harder to read than one that does not.
  if (!Commit(kStackBase, kStackSize)) return 0;
  std::memset(reinterpret_cast<void*>(uintptr_t(kStackBase)), 0, kStackSize);
  g_ready = true;
  return 1;
}

// ponytail: a bump allocator, and free() is a no-op. The ceiling is real and
// worth naming: nothing is ever reused, so a long session leaks until the
// arena is gone. It is sized against the machine this game shipped on -- an
// iPhone 3G had 128 MB of RAM in total, so 512 MB that is never reclaimed is a
// great deal more than the game can have been written to need, and running out
// is loud rather than silent. Swap in a free list the first time a real run
// exhausts it, not before.
uint32_t arc_guest_alloc(uint32_t size, uint32_t align) {
  if (!g_ready && !arc_mem_init()) return 0;
  if (align < 8) align = 8;
  const uint32_t base = (g_next + align - 1) & ~(align - 1);
  // A size that wraps is a corrupted length, not a big allocation; refuse it
  // rather than returning a pointer to a region that was never reserved.
  if (size > kHeapSize || base < g_next || base + size < base) return 0;
  if (base + size > kHeapBase + kHeapSize) return 0;
  while (base + size > g_committed) {
    const uint32_t want = g_committed + kChunk > kHeapBase + kHeapSize
                              ? kHeapBase + kHeapSize - g_committed
                              : kChunk;
    if (!want || !Commit(g_committed, want)) return 0;
    g_committed += want;
  }
  g_next = base + size;
  return base;
}

uint32_t arc_guest_calloc(uint32_t count, uint32_t size) {
  const uint64_t total = uint64_t(count) * size;
  if (total > kHeapSize) return 0;
  const uint32_t p = arc_guest_alloc(uint32_t(total), 8);
  if (p) std::memset(reinterpret_cast<void*>(uintptr_t(p)), 0, size_t(total));
  return p;
}

void arc_guest_free(uint32_t) {}

uint32_t arc_guest_strdup(const char* s) {
  if (!s) return 0;
  const uint32_t n = uint32_t(std::strlen(s)) + 1;
  const uint32_t p = arc_guest_alloc(n, 1);
  if (p) std::memcpy(reinterpret_cast<void*>(uintptr_t(p)), s, n);
  return p;
}

uint32_t arc_guest_stack_bottom(void) { return kStackBase; }

uint32_t arc_guest_stack_top(void) {
  // Sixteen bytes clear of the end and eight-aligned, which is what the
  // procedure call standard requires at a public entry point.
  return (kStackBase + kStackSize - 16) & ~7u;
}

int arc_guest_owns(uint32_t addr, uint32_t size) {
  if (addr + size < addr) return 0;
  if (addr >= kHeapBase && addr + size <= kHeapBase + kHeapSize) return 1;
  if (addr >= kStackBase && addr + size <= kStackBase + kStackSize) return 1;
  return 0;
}

namespace {
uint32_t g_image_lo = 0, g_image_hi = 0;
}  // namespace

void arc_set_image_range(uint32_t lo, uint32_t hi) {
  g_image_lo = lo;
  g_image_hi = hi;
}

int arc_guest_plausible(uint32_t addr) {
  if (!addr) return 0;
  if (addr >= g_image_lo && addr < g_image_hi) return 1;
  return arc_guest_owns(addr, 1);
}

size_t arc_guest_find(uint32_t value, uint32_t* out, size_t limit) {
  size_t found = 0;
  // Only what has actually been handed out, and the stack. Scanning reserved
  // but uncommitted address space would fault, which would be an unhelpful way
  // to answer a question about a fault.
  const struct {
    uint32_t lo, hi;
  } spans[] = {{kHeapBase, g_next}, {kStackBase, kStackBase + kStackSize}};
  for (const auto& s : spans) {
    for (uint32_t at = s.lo; at + 4 <= s.hi && found < limit; at += 4) {
      uint32_t word;
      memcpy(&word, reinterpret_cast<const void*>(uintptr_t(at)), 4);
      if (word == value && out) out[found++] = at;
    }
  }
  return found;
}

uint32_t arc_guest_used(void) { return g_next - kHeapBase; }
uint32_t arc_guest_capacity(void) { return kHeapSize; }
