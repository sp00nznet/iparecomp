// Memory the guest can hold a pointer to.
//
// This is the constraint that does not exist on the Android side and cannot be
// worked around: the guest is 32-bit and the host is not. A host `malloc`
// returns an address well above 4 GB, the guest stores it in a register, and
// the top half is gone. The failure is not a crash at the call -- it is a
// plausible-looking pointer that faults much later, somewhere unrelated.
//
// So everything the guest may hold the address of comes from here: its heap,
// its stack, and any buffer a shim hands back. The region is reserved low
// enough to be addressable in 32 bits, and every shim that returns a pointer
// allocates from it rather than from the host allocator.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Reserves the guest's address space. Call once, before anything guest-visible
// is allocated. Returns 0 if the ranges could not be taken, which is fatal:
// there is no fallback, because a higher address is not representable.
int arc_mem_init(void);

// The guest heap. Addresses are guaranteed to fit in 32 bits.
uint32_t arc_guest_alloc(uint32_t size, uint32_t align);
uint32_t arc_guest_calloc(uint32_t count, uint32_t size);
void arc_guest_free(uint32_t addr);

// Copy a host string into guest memory, returning its guest address.
uint32_t arc_guest_strdup(const char* s);

// The stack the guest runs on: the highest usable address, already aligned.
// It grows down from here, as the architecture expects.
uint32_t arc_guest_stack_top(void);

// Whether an address is inside anything the guest owns. A shim that is handed
// a pointer should ask before dereferencing it, because a guest that has gone
// wrong will hand over nonsense and the resulting fault is far less useful
// than a named refusal.
int arc_guest_owns(uint32_t addr, uint32_t size);

// How much of the heap has been handed out, for the report on the way down.
uint32_t arc_guest_used(void);
uint32_t arc_guest_capacity(void);

#ifdef __cplusplus
}
#endif
