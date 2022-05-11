// See LICENSE for license details.

#ifndef _PK_DUMP_H
#define _PK_DUMP_H

#include <stdint.h>
#include <stddef.h>

// System call trace record.
typedef struct {
  size_t args[7];
  size_t epc;
} strace_t;

// Platform version.
#define PLATINFO_MAJOR 0
#define PLATINFO_MINOR 1

// Platform information.
typedef struct {
  uint8_t magic[2];
  uint8_t endian;
  uint8_t ptr_size;
  uint32_t page_size;
  uint16_t major;
  uint16_t minor;
} platinfo_t;

// Current executable information.
typedef struct {
  uint32_t phent;
  uint32_t phnum;
  uint32_t is_supervisor;
  size_t phdr;
  size_t phdr_size;
  size_t bias;
  size_t entry;
  size_t brk_min;
  size_t brk;
  size_t brk_max;
  size_t mmap_max;
  size_t stack_top;
  size_t vm_alloc_guess;
} current_t;

// Performance counters.
typedef struct {
  uint64_t time;
  uint64_t cycle;
  uint64_t instret;
} counter_t;

// Floating point registers.
typedef struct {
  uint32_t status;
  uint32_t fcsr;
  uint64_t regs[32];
} fpregs_t;

// Kernel file descriptor data.
typedef struct {
  uint64_t offset;
  uint32_t flags;
  uint32_t path_len;
} kfd_t;

// VMR object data.
typedef struct {
  size_t addr;
  size_t length;
  size_t offset;
  uint32_t file;
  uint32_t prot;
  uint32_t refcnt;
  uint32_t __pad0;
} vmr_data_t;

// Physical mapping record.
#define PMAP_PA_SHIFT 11
#define PMAP_PA (1 << PMAP_PA_SHIFT)
#define PMAP_PR_SHIFT 10
#define PMAP_PR (1 << PMAP_PR_SHIFT)
#define PMAP_PA_PR (PMAP_PA | PMAP_PR)

// VMR mapping record.
typedef struct {
  size_t vaddr;
  size_t id;
} vmap_record_t;

#endif
