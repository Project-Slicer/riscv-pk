// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "file.h"
#include "frontend.h"
#include "syscall.h"
#include "mmap.h"
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
const char* restore_file; // set by -r flag

static uint64_t last_checkpoint_cycle;
static int dir_fd, syscall_trace_fd;

// System call trace record.
typedef struct {
  size_t args[7];
  size_t epc;
} strace_t;

// Wrapper of system call `openat`.
static inline int openat(int dir_fd, const char* path, int flags, mode_t mode)
{
  size_t path_size = strlen(path) + 1;
  return frontend_syscall(SYS_openat, dir_fd, kva2pa(path), path_size, flags, mode, 0, 0);
}

// Wrapper of system call `write`.
static inline ssize_t write(int fd, const void* buf, size_t count)
{
  return frontend_syscall(SYS_write, fd, kva2pa(buf), count, 0, 0, 0, 0);
}

// Traces system calls and dumps them to the trace file.
static void trace_syscall(const trapframe_t* tf)
{
  strace_t strace;
  for (size_t i = 0; i < 6; i++)
    strace.args[i] = tf->gpr[10 + i];
  strace.args[6] = tf->gpr[17];
  strace.epc = tf->epc;
  write(syscall_trace_fd, &strace, sizeof(strace));
}

// Performs checkpoint operation.
static void do_checkpoint(const trapframe_t* tf)
{
  // TODO
  printk("checkpointing not implemented\n");
  if (checkpoint_dir)
    printk("  checkpoint directory: %s\n", checkpoint_dir);
}

void slicer_init()
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // initialize cycle counter
  last_checkpoint_cycle = rdcycle64();

  // initialize checkpoint directory
  if (checkpoint_dir) {
    dir_fd = openat(AT_FDCWD, checkpoint_dir, O_DIRECTORY, 0);
    if (dir_fd < 0)
      panic("failed to open checkpoint directory: %s", checkpoint_dir);
  } else {
    dir_fd = AT_FDCWD;
  }

  // initialize syscall trace file
  syscall_trace_fd = openat(dir_fd, "strace", O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (syscall_trace_fd < 0)
    panic("failed to open syscall trace file");
}

void slicer_syscall_handler(const void* tf)
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // trace system call
  trace_syscall((const trapframe_t*)tf);

  // perform checkpoint
  kassert(CLOCK_FREQ % 1000 == 0);
  if ((rdcycle64() - last_checkpoint_cycle) / (CLOCK_FREQ / 1000) >= checkpoint_interval) {
    do_checkpoint((const trapframe_t*)tf);
    last_checkpoint_cycle = rdcycle64();
  }
}
