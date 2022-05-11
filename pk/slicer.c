// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "syscall.h"
#include "flush_icache.h"
#include "ksyscall.h"
#include "checkpoint.h"
#include "dump.h"
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
int compress_mem_dump; // set by --compress flag
int dump_file_contents; // set by --dump-file flag
const char* restore_dir; // set by -r flag
int dir_fd; // used by `ksyscall.h` and `checkpoint.c`

static uint64_t last_checkpoint_instret;
static int strace_fd;
static size_t checkpoint_id;

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

// Marks PA bits in the `pmap` file of the last checkpoint.
static void mark_last_pa_bits()
{
  // TODO
}

// Marks PR bits in the `pmap` file of the last checkpoint.
static void mark_last_pr_bits()
{
  // TODO
}

// Compresses the memory dump of the last checkpoint.
static void compress_last_mem_dump()
{
  // TODO
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
}

void slicer_syscall_handler(const void* tf)
{
  if (checkpoint_interval) {
    switch (((trapframe_t*)tf)->gpr[17]) {
      case SYS_exit:
      case SYS_exit_group:
      case SYS_tgkill: {
        if (compress_mem_dump)
          compress_last_mem_dump();
        move_syscall_trace(dir_fd);
        break;
      }
      case SYS_mmap:
      case SYS_munmap: {
        if (compress_mem_dump)
          mark_last_pa_bits();
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

void slicer_syscall_post_handler(const void* tf)
{
  long syscall_num = ((trapframe_t*)tf)->gpr[17];
  if (compress_mem_dump &&
      (syscall_num == SYS_mmap || syscall_num == SYS_munmap)) {
    mark_last_pr_bits();
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
  if (compress_mem_dump)
    compress_last_mem_dump();

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
