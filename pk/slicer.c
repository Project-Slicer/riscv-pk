// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "file.h"
#include "frontend.h"
#include "syscall.h"
#include "mmap.h"
#include "boot.h"
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

// Platform information.
typedef struct {
  uint8_t magic[2];
  uint8_t endian;
  uint8_t ptr_size;
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

// Wrapper of system call `close`.
static inline int close(int fd)
{
  return frontend_syscall(SYS_close, fd, 0, 0, 0, 0, 0, 0);
}

// Opens and creates a write-only file at the checkpoint directory, or panics if it fails.
static inline int open_assert(const char* path) {
  int fd = openat(dir_fd, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    panic("failed to open `%s'", path);
  return fd;
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

// Dumps platform information.
static void dump_platinfo() {
  platinfo_t platinfo;
  platinfo.magic[0] = 'p';
  platinfo.magic[1] = 'i';
#ifdef __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  platinfo.endian = 0;
#else
  platinfo.endian = 1;
#endif
  platinfo.ptr_size = sizeof(void*);
  int fd = open_assert("platinfo");
  write(fd, &platinfo, sizeof(platinfo));
  close(fd);
}

// Dumps current executable's information.
static void dump_current() {
  current_t cur = {
    .phent = current.phent,
    .phnum = current.phnum,
    .is_supervisor = current.is_supervisor,
    .phdr = current.phdr,
    .phdr_size = current.phdr_size,
    .bias = current.bias,
    .entry = current.entry,
    .brk_min = current.brk_min,
    .brk = current.brk,
    .brk_max = current.brk_max,
    .mmap_max = current.mmap_max,
    .stack_top = current.stack_top,
    .vm_alloc_guess = current.vm_alloc_guess,
  };
  int fd = open_assert("current");
  write(fd, &cur, sizeof(cur));
  close(fd);
}

// Dumps performance counters.
static void dump_counter() {
  counter_t counter = {
    .time = rdtime64(),
    .cycle = rdcycle64(),
    .instret = rdinstret64(),
  };
  int fd = open_assert("counter");
  write(fd, &counter, sizeof(counter));
  close(fd);
}

// Dumps trapframe.
static void dump_trapframe(const trapframe_t* tf) {
  int fd = open_assert("tf");
  write(fd, tf, sizeof(*tf));
  close(fd);
}

// Performs checkpoint operation.
static void do_checkpoint(const trapframe_t* tf)
{
  // TODO
  dump_platinfo();
  dump_current();
  dump_counter();
  dump_trapframe(tf);
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
