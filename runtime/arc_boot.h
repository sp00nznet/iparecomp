// Starting the guest, and saying where it stopped.
//
// The second half is the point. A fault in lifted code names an address in the
// data it touched and never the code that touched it, and the host call stack
// is tens of thousands of identically shaped C functions -- so a bare crash
// says almost nothing. What says something is the guest's own trail: which
// lifted functions were entered, and which calls went out to the host with
// what arguments. Both rings already exist in the runtime; this is what reads
// them back.
#pragma once

#include <string>

#include "arm32_context.h"
#include "macho_image.h"

namespace arc {

struct BootResult {
  bool started = false;   // the entry point was reached at all
  bool trapped = false;   // it stopped somewhere the lift could not express
  bool exited = false;    // it ran to the end and called exit
  int exit_code = 0;
  std::string trap;       // what arc_trap was told, when it was
  uint32_t entry = 0;
  size_t shims = 0;       // imports a shim claimed
  size_t outstanding = 0; // imports still owed by a framework
  size_t bound_classes = 0; // framework class references dyld would have filled
  size_t bound_slots = 0;   // import pointer slots pointed at their stubs
  size_t synthetic = 0;     // imports the linker gave no stub, given one here
};

// Sets up the guest's memory, installs every shim this library has, points
// objc_msgSend at the realized class table, and calls the image's entry point.
//
// `install_lifted` is what the generated program supplies -- the library
// cannot name it, because only the generated module knows the address table.
// Pass null to run with no lifted code at all, which is still useful: it says
// what the shim surface looks like before any of it can be exercised.
BootResult Boot(MachOImage& img, void (*install_lifted)(uint32_t),
                bool permissive = false);

// Where the .app's resources are. Images and any file the guest opens are
// resolved from here.
void SetBundlePath(const std::string& path);

// Catch a hardware fault and describe it before the process dies.
//
// A trap is the lift saying it cannot express something, and that path prints
// a trail. A *fault* is the guest touching memory that is not there, and by
// default it prints nothing at all -- the least useful outcome, since the host
// call stack is thousands of identically shaped C functions and the faulting
// address names the data rather than the code. This installs a handler that
// reports the address, what the OS says is at it, and the same trail a trap
// would have given.
void InstallFaultHandler(const MachOImage& img);

// What the guest was doing, most recent first. Safe to call after a trap.
void ReportTrail(const MachOImage& img);

}  // namespace arc
