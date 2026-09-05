#include "arc_boot.h"

#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <deque>

#include "arc_mem.h"
#include "objc_host.h"
#include "objc_runtime.h"

namespace arc {

size_t InstallLibSystemShims(const MachOImage& img);
size_t InstallUIKitShims(const MachOImage& img);

namespace {

// dyld hands `_start` a very specific stack, and `_start` reads all of it
// before it ever reaches main: argc, then argv with its terminator, then the
// environment with its terminator, then the apple[] vector. Canabalt's own
// entry walks the environment looking for the end, so a missing terminator is
// not a detail -- it is an unbounded loop through whatever follows.
uint32_t BuildStack(const MachOImage& img) {
  const uint32_t top = arc_guest_stack_top();
  const uint32_t name = arc_guest_strdup("Canabalt");
  (void)img;

  // argc, argv[0], argv terminator, envp terminator, apple terminator.
  const uint32_t words = 5;
  uint32_t sp = (top - words * 4) & ~7u;
  uint32_t* p = reinterpret_cast<uint32_t*>(uintptr_t(sp));
  p[0] = 1;      // argc
  p[1] = name;   // argv[0]
  p[2] = 0;      // argv terminator
  p[3] = 0;      // envp terminator
  p[4] = 0;      // apple terminator
  return sp;
}

const char* NameOf(const MachOImage& img, uint32_t addr) {
  static std::map<uint32_t, std::string> names;
  if (names.empty())
    for (const auto& e : img.exports()) names.emplace(e.addr, e.name);
  auto it = names.upper_bound(addr);
  if (it == names.begin()) return nullptr;
  --it;
  return it->second.c_str();
}

}  // namespace

BootResult Boot(const MachOImage& img, void (*install_lifted)(uint32_t),
                bool permissive) {
  BootResult r;
  SetPermissive(permissive);
  if (!arc_mem_init()) {
    r.trap = "could not reserve the guest's address space below 4 GB";
    return r;
  }

  r.shims = InstallLibSystemShims(img);
  r.shims += InstallUIKitShims(img);
  if (Objc().Init(img)) InstallObjcRuntime(img);
  // Host classes first, then the bind sites that point at them. Without this
  // every __objc_classrefs slot reads zero, and a message to nil is answered
  // with zero rather than refused -- so the failure would surface much later
  // and somewhere unrelated.
  InstallFoundationClasses();
  r.bound_classes = BindHostClasses(img);
  if (install_lifted) install_lifted(img.link_base());

  // Everything with a stub and no shim gets registered by name, so reaching
  // one reports what to write next instead of an address. Registration is
  // idempotent and the real shims went in first, so this only fills the gaps.
  static std::deque<std::string> kept;
  for (const auto& im : img.imports()) {
    if (!im.stub) continue;
    kept.push_back(im.name);
    const char* name = kept.back().c_str();
    kept.push_back(im.dylib);
    arc_register_stub(im.stub, name, kept.back().c_str());
    ++r.outstanding;
  }
  // What the shims already answer is not outstanding.
  r.outstanding = r.outstanding > r.shims ? r.outstanding - r.shims : 0;

  r.entry = img.entry();
  if (!r.entry) {
    r.trap = "the image declares no entry point";
    return r;
  }

  Arm32Ctx ctx;
  std::memset(&ctx, 0, sizeof ctx);
  ctx.image_base = img.link_base();
  ARC_W(&ctx, 13, BuildStack(img));
  // A return address the dispatcher will never find, so a guest that returns
  // from its entry point stops somewhere describable instead of branching to
  // zero.
  ARC_W(&ctx, 14, 0xDEAD0000u);

  arc_trace_clear();
  arc_frame_clear();

  std::jmp_buf recovery;
  arc_set_recovery(&recovery);
  r.started = true;
  if (setjmp(recovery) == 0) {
    arc_dispatch(&ctx, r.entry);
  } else {
    r.trapped = true;
    r.trap = arc_last_trap();
  }
  arc_set_recovery(nullptr);
  return r;
}

void ReportTrail(const MachOImage& img) {
  const auto& missing = MissingMessages();
  if (!missing.empty()) {
    std::printf("\nmessages answered with nil because nothing implements them "
                "(%zu):\n", missing.size());
    for (const auto& m : missing)
      std::printf("  %-28s %s\n", m.first.c_str(), m.second.c_str());
  }

  const size_t frames = arc_frame_count();
  if (frames) {
    std::printf("\nguest functions entered, most recent first:\n");
    for (size_t i = 0; i < frames && i < 20; ++i) {
      const uint32_t a = arc_frame_at(i);
      const char* n = NameOf(img, a);
      std::printf("  %#010x  %s\n", a, n ? n : "");
    }
  } else {
    std::printf(
        "\nno guest frames recorded -- build the lifted program with\n"
        "ARC_FRAMES defined to get a backtrace through it.\n");
  }

  const size_t calls = arc_trace_count();
  if (calls) {
    std::printf("\ncalls out to the host, most recent first:\n");
    for (size_t i = 0; i < calls && i < 20; ++i)
      std::printf("  %s\n", arc_trace_at(i));
  }

  std::printf("\nguest heap: %u of %u bytes handed out\n", arc_guest_used(),
              arc_guest_capacity());
}

}  // namespace arc
