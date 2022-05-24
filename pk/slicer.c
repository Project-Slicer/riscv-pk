// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "syscall.h"
#include "flush_icache.h"
#include "ksyscall.h"
#include "checkpoint.h"
#include "dump.h"
#include "mmap.h"
#include "boot.h"
#include "bits.h"
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

// Command line options.
size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
int dump_accessed_mem; // set by --dump-accessed flag
int compress_mem_dump; // set by --compress flag
int dump_file_contents; // set by --dump-file flag
const char* restore_dir; // set by -r flag
int fuzzy_check_strace; // set by --fuzzy-strace flag
int dir_fd; // used by `ksyscall.h` and `checkpoint.c`

// For slicer.
static uint64_t last_checkpoint_instret;
static int strace_fd;
static size_t checkpoint_id;

// For memory dump compression.
static size_t *pmap_cache;
static uintptr_t msyscall_vaddr;
static size_t msyscall_len;
#define MAX_COMPRESSORS 64
static struct {
  uint32_t id;
  int dir_fd;
} compressors[MAX_COMPRESSORS];
static size_t compressor_count;

// Traces system calls and dumps them to the trace file.
static void trace_syscall(const trapframe_t* tf)
{
  strace_t strace;
  for (size_t i = 0; i < 6; i++)
    strace.args[i] = tf->gpr[10 + i];
  strace.args[6] = tf->gpr[17];
  strace.epc = tf->epc;
  write_assert(strace_fd, &strace, sizeof(strace));
}

// Checks for system call trace.
static bool check_syscall_trace(const trapframe_t* tf)
{
  strace_t strace;
  ssize_t len = sys_read(strace_fd, &strace, sizeof(strace));
  if (len == 0) {
    sys_exit(0);
  } else if (len < 0 || (size_t)len != sizeof(strace)) {
    return false;
  } else {
    if (!fuzzy_check_strace) {
      for (size_t i = 0; i < 6; i++) {
        if (strace.args[i] != tf->gpr[10 + i])
          return false;
      }
    }
    if (strace.args[6] != tf->gpr[17] || strace.epc != tf->epc)
      return false;
  }
  return true;
}

// Gets the checkpoint directory name by the given checkpoint id.
static const char* get_checkpoint_dir_name(size_t id)
{
  static char dir_name[sizeof("0123456789")];
  int ret = snprintf(dir_name, sizeof(dir_name), "%ld", id);
  kassert(ret < sizeof(dir_name));
  return dir_name;
}

// Moves the system call trace file to the last checkpoint directory.
static void move_syscall_trace(int dir_fd)
{
  close_assert(strace_fd);
  int fd = sys_openat(dir_fd, get_checkpoint_dir_name(checkpoint_id - 1),
                      O_DIRECTORY, 0);
  int ret = sys_renameat(dir_fd, "strace", fd, "strace");
  kassert(ret == 0);
  close_assert(fd);
}

// Updates the `pmap` file of the last checkpoint.
static void update_last_pmap(bool (*callback)(uintptr_t, size_t*))
{
  // open the pmap file
  int last_dir_fd = sys_openat(
      dir_fd, get_checkpoint_dir_name(checkpoint_id - 1), O_DIRECTORY, 0);
  int pmap_fd = sys_openat(last_dir_fd, "mem/pmap", O_RDWR, 0);
  kassert(pmap_fd >= 0);

  // update the file by the callback
  size_t offset = 0;
  ssize_t len;
  while ((len = sys_read(pmap_fd, pmap_cache, RISCV_PGSIZE)) > 0) {
    bool modified = false;
    for (size_t i = 0; i < len / sizeof(size_t); i++) {
      if (pmap_cache[i] & PMAP_PA_PR)
        continue;
      uintptr_t vaddr = pmap_cache[i] & ~((1 << RISCV_PGSHIFT) - 1);
      if (callback(vaddr, &pmap_cache[i]))
        modified = true;
    }
    // write back
    if (modified) {
      ssize_t ret = sys_pwrite(pmap_fd, pmap_cache, len, offset);
      kassert(ret == len);
    }
    offset += len;
  }
  kassert(len == 0);

  // close the pmap file
  close_assert(pmap_fd);
  close_assert(last_dir_fd);
}

// Marks PA-bit of a `pmap` entry.
static bool mark_pa_bit(uintptr_t vaddr, size_t* entry)
{
  if (page_accessed(vaddr)) {
    *entry |= PMAP_PA;
    return true;
  }
  return false;
}

// Marks PR-bit of a `pmap` entry.
static bool mark_pr_bit(uintptr_t vaddr, size_t* entry)
{
  if (vaddr >= msyscall_vaddr && vaddr < msyscall_vaddr + msyscall_len) {
    *entry |= PMAP_PR;
    return true;
  }
  return false;
}

// Removes the unaccessed pages from the last memory dump.
static void remove_unaccessed_pages(int dir_fd)
{
  // open the pmap & page file
  int last_dir_fd = sys_openat(
      dir_fd, get_checkpoint_dir_name(checkpoint_id - 1), O_DIRECTORY, 0);
  int pmap_fd = sys_openat(last_dir_fd, "mem/pmap", O_RDWR, 0);
  int page_fd = sys_openat(last_dir_fd, "mem/page", O_RDWR, 0);
  kassert(pmap_fd >= 0 && page_fd >= 0);

  // check the first byte of the page file
  uint8_t first_byte;
  read_assert(page_fd, &first_byte, 1);
  kassert(first_byte == 0);

  // update file
  size_t ri = 0, wi = 0, pmap_entry;
  ssize_t len, ret;
  while ((len = sys_read(pmap_fd, &pmap_entry, sizeof(pmap_entry))) > 0) {
    // check if the page is accessed
    bool accessed = false;
    if (pmap_entry & PMAP_PA) {
      accessed = true;
    } else if (!(pmap_entry & PMAP_PR)) {
      uintptr_t vaddr = pmap_entry & ~((1 << RISCV_PGSHIFT) - 1);
      accessed = page_accessed(vaddr);
    }
    // keep the accessed page only
    if (accessed) {
      if (wi != ri) {
        ret = sys_pwrite(pmap_fd, &pmap_entry, sizeof(pmap_entry),
                         wi * sizeof(pmap_entry));
        kassert(ret == sizeof(pmap_entry));
        ret = sys_pread(page_fd, pmap_cache, RISCV_PGSIZE, 1 + ri * RISCV_PGSIZE);
        kassert(ret == RISCV_PGSIZE);
        ret = sys_pwrite(page_fd, pmap_cache, RISCV_PGSIZE, 1 + wi * RISCV_PGSIZE);
        kassert(ret == RISCV_PGSIZE);
      }
      wi++;
    }
    ri++;
  }
  kassert(len == 0);

  // truncate file
  if (wi != ri) {
    ret = sys_ftruncate(pmap_fd, wi * sizeof(pmap_entry));
    kassert(ret == 0);
    ret = sys_ftruncate(page_fd, 1 + wi * RISCV_PGSIZE);
    kassert(ret == 0);
  }

  // close the pmap & page file
  close_assert(pmap_fd);
  close_assert(page_fd);
  close_assert(last_dir_fd);
}

// Frees the compressors.
static void free_compressors()
{
  size_t new_count = 0;
  for (size_t i = 0; i < compressor_count; i++) {
    int result = compressquery_assert(compressors[i].id);
    if (result == 1) {
      panic("failed to compress memory dump");
    } else if (result == 0) {
      close_assert(compressors[i].dir_fd);
    } else {
      if (new_count != i)
        compressors[new_count] = compressors[i];
      new_count++;
    }
  }
  compressor_count = new_count;
}

// Compresses the last memory dump.
static void compress_last_mem_dump(int dir_fd)
{
  // wait for the compressors to finish
  while (compressor_count == MAX_COMPRESSORS)
    free_compressors();

  // create a new compressor
  int last_dir_fd = sys_openat(
      dir_fd, get_checkpoint_dir_name(checkpoint_id - 1), O_DIRECTORY, 0);
  kassert(last_dir_fd >= 0);
  compressors[compressor_count].id =
      compressfile_assert(last_dir_fd, "mem/page");
  compressors[compressor_count].dir_fd = last_dir_fd;
  compressor_count++;
}

// Clears the A-bit and D-bit of the page table entry.
static void clear_ad(uintptr_t vaddr, pte_t* pte, const void* p, int is_vmr)
{
  if (!is_vmr) {
    *pte &= ~(PTE_A | PTE_D);
    flush_tlb_entry(vaddr);
  }
}

// Performs some necessary operations before exiting.
static void exit_handler()
{
  if (checkpoint_id) {
    if (dump_accessed_mem)
      remove_unaccessed_pages(dir_fd);
    if (compress_mem_dump) {
      compress_last_mem_dump(dir_fd);
      // wait for all compressors to finish
      while (compressor_count)
        free_compressors();
    }
  }
  move_syscall_trace(dir_fd);
}

// Performs some necessary operations before memory system calls.
static void msyscall_handler(const trapframe_t* tf)
{
  if (tf->gpr[17] == SYS_brk) {
    msyscall_vaddr = current.brk == 0 ? ROUNDUP(current.brk_min, RISCV_PGSIZE)
                                      : current.brk;
  } else {
    msyscall_vaddr = tf->gpr[10];
  }
  msyscall_len = tf->gpr[11];
  update_last_pmap(mark_pa_bit);
}

// Performs some necessary operations after memory system calls.
static void msyscall_post_handler(const trapframe_t* tf)
{
  // update vaddr and len
  switch (tf->gpr[17]) {
    case SYS_mmap: {
      if (tf->gpr[10] == -1)
        return;
      msyscall_vaddr = tf->gpr[10];
      break;
    }
    case SYS_munmap: {
      break;
    }
    case SYS_brk: {
      if (current.brk == msyscall_vaddr) {
        return;
      } else if (current.brk < msyscall_vaddr) {
        msyscall_len = msyscall_vaddr - current.brk;
        msyscall_vaddr = current.brk;
      } else {
        msyscall_len = current.brk - msyscall_vaddr;
      }
      break;
    }
    default: {
      return;
    }
  }

  // update last pmap
  update_last_pmap(mark_pr_bit);
}

void slicer_init()
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // initialize checkpoint directory
  if (checkpoint_dir) {
    dir_fd = sys_openat(AT_FDCWD, checkpoint_dir, O_DIRECTORY, 0);
    if (dir_fd == -ENOENT) {
      if (sys_mkdirat(AT_FDCWD, checkpoint_dir, 0755) < 0)
        panic("failed to create checkpoint directory: %s", checkpoint_dir);
      dir_fd = sys_openat(AT_FDCWD, checkpoint_dir, O_DIRECTORY, 0);
    }
    if (dir_fd < 0)
      panic("failed to open checkpoint directory: %s", checkpoint_dir);
  } else {
    dir_fd = AT_FDCWD;
  }

  // initialize syscall trace file
  strace_fd = openw_assert("strace");

  // initialize pmap cache
  pmap_cache = (void*)pa2kva(__page_alloc_assert());
}

void slicer_syscall_handler(const void* t)
{
  const trapframe_t* tf = (const trapframe_t*)t;
  if (checkpoint_interval) {
    switch (tf->gpr[17]) {
      case SYS_exit:
      case SYS_exit_group:
      case SYS_tgkill: {
        exit_handler();
        break;
      }
      case SYS_mmap:
      case SYS_munmap:
      case SYS_brk: {
        if (dump_accessed_mem && checkpoint_id)
          msyscall_handler(tf);
        break;
      }
      default: {
        // perform checkpoint
        if (rdinstret64() - last_checkpoint_instret >= checkpoint_interval)
          slicer_checkpoint(tf);
        // trace system call
        trace_syscall(tf);
        break;
      }
    }
  } else if (restore_dir) {
    // check system call trace
    if (!check_syscall_trace(tf))
      panic("system call trace mismatch");
  }
}

void slicer_syscall_post_handler(const void* t)
{
  const trapframe_t* tf = (const trapframe_t*)t;
  if (dump_accessed_mem && checkpoint_id)
    msyscall_post_handler(tf);
}

void slicer_checkpoint(const void* tf)
{
  // make checkpoint directory
  const char* dir_name = get_checkpoint_dir_name(checkpoint_id);
  mkdir_assert(dir_name);

  // change directory to the checkpoint directory
  int old_dir_fd = dir_fd;
  dir_fd = sys_openat(old_dir_fd, dir_name, O_DIRECTORY, 0);

  // do checkpoint
  do_checkpoint(tf);
  if (dump_accessed_mem) {
    if (checkpoint_id)
      remove_unaccessed_pages(old_dir_fd);
    dump_page_table(clear_ad);
  }
  if (compress_mem_dump && checkpoint_id)
    compress_last_mem_dump(old_dir_fd);

  // update system call trace
  if (checkpoint_id) {
    move_syscall_trace(old_dir_fd);
    strace_fd = sys_openat(old_dir_fd, "strace", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  }

  // update checkpoint cycle counter
  last_checkpoint_instret = rdinstret64();

  // restore directory
  close_assert(dir_fd);
  dir_fd = old_dir_fd;
  ++checkpoint_id;
}

void slicer_restore(uintptr_t kstack_top)
{
  // initialize restore directory
  dir_fd = sys_openat(AT_FDCWD, restore_dir, O_DIRECTORY, 0);
  if (dir_fd < 0)
    panic("failed to open checkpoint directory: %s", restore_dir);

  // restore from the given checkpoint
  trapframe_t tf;
  do_restore(&tf);

  // open system call trace
  strace_fd = openr_assert("strace");

  // TODO: remove if supports microarchitectural state restoration
  __riscv_flush_icache();
  write_csr(sscratch, kstack_top);
  start_user(&tf);
}
