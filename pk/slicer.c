// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "syscall.h"
#include "flush_icache.h"
#include "ksyscall.h"
#include "checkpoint.h"
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
int compress_mem_dump; // set by --compress flag
int dump_file_contents; // set by --dump-file flag
const char* restore_dir; // set by -r flag
int dir_fd; // used by `ksyscall.h` and `checkpoint.c`

static uint64_t last_checkpoint_cycle;
static int strace_fd;

void slicer_init()
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // initialize cycle counter
  kassert(CLOCK_FREQ % 1000 == 0);
  last_checkpoint_cycle = rdcycle64();

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

// Checks if it's time to checkpoint.
static inline bool should_checkpoint(const trapframe_t* tf)
{
  bool meet_interval =
      (rdcycle64() - last_checkpoint_cycle) / (CLOCK_FREQ / 1000) >=
      checkpoint_interval;
  return meet_interval;
}

void slicer_syscall_handler(const void* tf)
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // trace system call
  trace_syscall(strace_fd, tf);

  // perform checkpoint
  if (should_checkpoint(tf)) {
    do_checkpoint(tf);
    last_checkpoint_cycle = rdcycle64();

    // TODO: remove
    panic("checkpointed");
  }
}

void slicer_syscall_post_handler(const void* tf)
{
  // TODO
}

void slicer_restore(uintptr_t kstack_top)
{
  // initialize restore directory
  dir_fd = sys_openat(AT_FDCWD, restore_dir, O_DIRECTORY, 0);
  if (dir_fd < 0)
    panic("failed to open checkpoint directory: %s", restore_dir);

  trapframe_t tf;
  do_restore(&tf);

  // TODO: system call trace

  // TODO: remove if supports microarchitectural state restoration
  __riscv_flush_icache();
  write_csr(sscratch, kstack_top);
  start_user(&tf);
}
