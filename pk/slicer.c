// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "file.h"
#include <stdint.h>

size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
const char* restore_file; // set by -r flag

static uint64_t last_checkpoint_cycle;
static file_t* syscall_trace_file;

// Traces system calls and dumps them to the trace file.
static void trace_syscall(const trapframe_t* tf)
{
  // TODO
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

  last_checkpoint_cycle = rdcycle64();
}

void slicer_syscall_handler(const void* tf)
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  kassert(CLOCK_FREQ % 1000 == 0);
  if ((rdcycle64() - last_checkpoint_cycle) / (CLOCK_FREQ / 1000) >= checkpoint_interval) {
    trace_syscall((const trapframe_t*)tf);
    do_checkpoint((const trapframe_t*)tf);

    last_checkpoint_cycle = rdcycle64();
  }
}
