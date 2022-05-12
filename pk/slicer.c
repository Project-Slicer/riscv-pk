// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "syscall.h"
#include "flush_icache.h"
#include "ksyscall.h"
#include "checkpoint.h"
#include "dump.h"
#include "mmap.h"
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

// Command line options.
size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
int compress_mem_dump; // set by --compress flag
int dump_file_contents; // set by --dump-file flag
const char* restore_dir; // set by -r flag
int dir_fd; // used by `ksyscall.h` and `checkpoint.c`

// For slicer.
static uint64_t last_checkpoint_instret;
static int strace_fd;
static size_t checkpoint_id;

// For memory dump compressor.
static size_t *pmap_cache;
static uintptr_t msyscall_vaddr;
static size_t msyscall_len;

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
    for (size_t i = 0; i < 6; i++) {
      if (strace.args[i] != tf->gpr[10 + i])
        return false;
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
  while ((len = sys_read(pmap_fd, pmap_cache, sizeof(pmap_cache))) > 0) {
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
  if (page_accessed(vaddr))
    *entry |= PMAP_PA;
}

// Marks PR-bit of a `pmap` entry.
static bool mark_pr_bit(uintptr_t vaddr, size_t* entry)
{
  if (vaddr >= msyscall_vaddr && vaddr < msyscall_vaddr + msyscall_len)
    *entry |= PMAP_PR;
}

// Compresses the memory dump of the last checkpoint.
static void compress_last_mem_dump(int dir_fd)
{
  // open the pmap file
  int last_dir_fd = sys_openat(
      dir_fd, get_checkpoint_dir_name(checkpoint_id - 1), O_DIRECTORY, 0);
  int pmap_fd = sys_openat(last_dir_fd, "mem/pmap", O_RDWR, 0);
  int page_fd = sys_openat(last_dir_fd, "mem/page", O_RDWR, 0);
  kassert(pmap_fd >= 0);

  size_t offset = 0;
  ssize_t len;
  while ((len = sys_read(pmap_fd, pmap_cache, sizeof(pmap_cache))) > 0) {
    // TODO
  }

  // close the pmap file
  close_assert(pmap_fd);
  close_assert(last_dir_fd);
}

// Clears the A-bit and D-bit of the page table entry.
static void clear_ad(uintptr_t vaddr, pte_t* pte, const void* p, int is_vmr)
{
  if (!is_vmr) {
    *pte &= ~(PTE_A | PTE_D);
    flush_tlb_entry(vaddr);
  }
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
  pmap_cache = __page_alloc_assert();
}

void slicer_syscall_handler(const void* t)
{
  const trapframe_t* tf = (const trapframe_t*)t;
  if (checkpoint_interval) {
    switch (tf->gpr[17]) {
      case SYS_exit:
      case SYS_exit_group:
      case SYS_tgkill: {
        if (compress_mem_dump)
          compress_last_mem_dump(dir_fd);
        move_syscall_trace(dir_fd);
        break;
      }
      case SYS_mmap:
      case SYS_munmap: {
        if (compress_mem_dump) {
          msyscall_vaddr = tf->gpr[10];
          msyscall_len = tf->gpr[11];
          update_last_pmap(mark_pa_bit);
        }
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
  if (compress_mem_dump) {
    if (tf->gpr[17] == SYS_mmap && tf->gpr[10] != -1) {
      msyscall_vaddr = tf->gpr[10];
      update_last_pmap(mark_pr_bit);
    } else if (tf->gpr[17] == SYS_munmap) {
      update_last_pmap(mark_pr_bit);
    }
  }
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
  if (compress_mem_dump) {
    compress_last_mem_dump(old_dir_fd);
    dump_page_table(clear_ad);
  }

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
