#include "arc_boot.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <deque>

#include "arc_mem.h"
#include "objc_host.h"
#include "window.h"
#include "objc_runtime.h"

namespace arc {

size_t InstallLibSystemShims(const MachOImage& img);
size_t InstallUIKitShims(const MachOImage& img);
bool GuestExited(int* code);
void InstallObjectShims();
void InstallClassHierarchy();
void InstallUIKitObjects();
size_t InstallGlShims(const MachOImage& img);
size_t InstallAudioShims(const MachOImage& img);
size_t InstallFoundationCImports(const MachOImage& img);
size_t InstallCoreGraphicsShims(const MachOImage& img);
size_t InstallImageShims(const MachOImage& img);
size_t InstallFontShims(const MachOImage& img);
void SetBundlePath(const std::string& p);

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

namespace {

const MachOImage* g_fault_image = nullptr;

// What the OS says is at an address. The difference between a wild pointer and
// a real region touched the wrong way is most of the diagnosis, and only the
// OS knows which it is.
void DescribeAddress(uintptr_t at) {
#if defined(_WIN32)
  MEMORY_BASIC_INFORMATION mbi;
  if (!VirtualQuery(reinterpret_cast<LPCVOID>(at), &mbi, sizeof mbi)) {
    std::printf("  the address is not in this process's address space\n");
    return;
  }
  const char* state = mbi.State == MEM_COMMIT    ? "committed"
                      : mbi.State == MEM_RESERVE ? "reserved, not committed"
                                                 : "free";
  std::printf("  %p is %s", reinterpret_cast<void*>(at), state);
  if (mbi.State == MEM_COMMIT)
    std::printf(", protection %#lx", static_cast<unsigned long>(mbi.Protect));
  std::printf("\n");
#else
  std::printf("  %p\n", reinterpret_cast<void*>(at));
#endif
}

#if defined(_WIN32)
// A *vectored* handler, not an unhandled-exception filter. The C runtime
// installs its own SEH chain, so the filter never ran; a vectored handler is
// called before any of that, which is the only place a report is guaranteed to
// happen. It reports and then lets normal handling continue, so the process
// still dies the way it would have.
LONG WINAPI OnFault(EXCEPTION_POINTERS* info) {
  const DWORD code = info->ExceptionRecord->ExceptionCode;
  if (code != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
  const ULONG_PTR kind = info->ExceptionRecord->ExceptionInformation[0];
  const uintptr_t at = uintptr_t(info->ExceptionRecord->ExceptionInformation[1]);
  std::printf("\nthe guest faulted: %s %p\n",
              kind == 0   ? "reading"
              : kind == 1 ? "writing"
                          : "executing",
              reinterpret_cast<void*>(at));
  DescribeAddress(at);
  // Executing an address that is mapped is the giveaway for calling guest
  // code natively -- it is machine code for another architecture.
  if (kind == 8)
    std::printf("  executing mapped memory means a guest address was called "
                "as if it were a host function\n");
  if (g_fault_image) ReportTrail(*g_fault_image);
  std::fflush(stdout);
  return EXCEPTION_CONTINUE_SEARCH;
}
#endif

}  // namespace

void InstallFaultHandler(const MachOImage& img) {
  g_fault_image = &img;
#if defined(_WIN32)
  AddVectoredExceptionHandler(1, OnFault);
#endif
}

BootResult Boot(MachOImage& img, void (*install_lifted)(uint32_t),
                bool permissive) {
  BootResult r;
  SetPermissive(permissive);
  arc_set_permissive(permissive ? 1 : 0);
  if (!arc_mem_init()) {
    r.trap = "could not reserve the guest's address space below 4 GB";
    return r;
  }

  // Not every import has a stub. `exit` is reached only through its pointer
  // slot, so the linker emitted no code for it anywhere -- and with nothing to
  // register a shim against, the slot stayed zero and `_start`'s tail call to
  // it branched to nothing, after main had run to completion. Inventing an
  // address in the guest heap gives every import one identity that a shim, the
  // native table and a pointer slot can all agree on.
  for (size_t i = 0; i < img.imports().size(); ++i) {
    const Import& im = img.imports()[i];
    if (im.stub || im.slots.empty()) continue;
    // 64 bytes, not 4. Some of these are not functions at all -- CGPointZero,
    // CGRectZero, the kSec* and kEAGL* keys -- and the guest reads a constant
    // out of them rather than branching to them. Zeroed memory is the right
    // answer for every one of those; four bytes would not be enough to read.
    if (const uint32_t at = arc_guest_alloc(64, 8)) {
      img.SetImportStub(i, at);
      ++r.synthetic;
    }
  }

  InstallFaultHandler(img);

  r.shims = InstallLibSystemShims(img);
  r.shims += InstallUIKitShims(img);
  r.shims += InstallGlShims(img);
  r.shims += InstallAudioShims(img);
  r.shims += InstallFoundationCImports(img);
  r.shims += InstallCoreGraphicsShims(img);
  r.shims += InstallImageShims(img);
  // After CoreGraphics, so the real font metrics win over the stubs.
  r.shims += InstallFontShims(img);
  if (Objc().Init(img)) InstallObjcRuntime(img);
  // Host classes first, then the bind sites that point at them. Without this
  // every __objc_classrefs slot reads zero, and a message to nil is answered
  // with zero rather than refused -- so the failure would surface much later
  // and somewhere unrelated.
  InstallClassHierarchy();
  InstallFoundationClasses();
  InstallObjectShims();
  InstallUIKitObjects();
  r.bound_classes = BindHostClasses(img);
  r.bound_slots = BindImportSlots(img);
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

  // Said before the guest starts, not after it finishes. A run that reaches
  // the frame loop does not finish, and printing the setup afterwards means
  // the most useful numbers are the ones you never see.
  std::printf("shims      %zu imports claimed, %zu still owed\n", r.shims,
              r.outstanding);
  std::printf("classrefs  %zu bound, %zu pointer slots filled, "
              "%zu imports given a synthetic address\n",
              r.bound_classes, r.bound_slots, r.synthetic);
  std::printf("entry      %#010x\n\n", r.entry);
  std::fflush(stdout);

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
  // Generous: the launch path enters a few hundred thousand functions, and a
  // real frame loop resets this on its first pass.
  arc_frame_budget(40000000);

  std::jmp_buf recovery;
  arc_set_recovery(&recovery);
  r.started = true;
  if (setjmp(recovery) == 0) {
    arc_dispatch(&ctx, r.entry);
  } else if (GuestExited(&r.exit_code)) {
    r.exited = true;
  } else {
    r.trapped = true;
    r.trap = arc_last_trap();
  }
  arc_set_recovery(nullptr);
  WindowClose();
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

  const size_t unbound = arc_missing_count();
  if (unbound) {
    std::printf("\nimports answered with zero because nothing implements them "
                "(%zu):\n", unbound);
    for (size_t i = 0; i < unbound; ++i)
      std::printf("  %s\n", arc_missing_at(i));
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
