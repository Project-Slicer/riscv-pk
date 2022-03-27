// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include <stdint.h>

size_t checkpoint_interval; // set by -c flag, milliseconds
const char *checkpoint_dir; // set by -d flag

static uint64_t last_checkpoint_cycle;

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

  uint64_t cycle = rdcycle64();
  kassert(CLOCK_FREQ % 1000 == 0);
  if ((cycle - last_checkpoint_cycle) / (CLOCK_FREQ / 1000) >= checkpoint_interval) {
    last_checkpoint_cycle = cycle;

    // TODO
    printk("checkpointing not implemented\n");
    if (checkpoint_dir)
      printk("  checkpoint directory: %s\n", checkpoint_dir);
  }
}
