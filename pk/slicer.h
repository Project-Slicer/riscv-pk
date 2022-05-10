// See LICENSE for license details.

#ifndef _PK_SLICER_H
#define _PK_SLICER_H

#include <stddef.h>
#include <stdint.h>

extern size_t checkpoint_interval;
extern const char* checkpoint_dir;
extern int compress_mem_dump;
extern int dump_file_contents;
extern const char* restore_dir;

void slicer_init();
void slicer_syscall_handler(const void* tf);
void slicer_syscall_post_handler(const void* tf);

// Dumps a checkpoint.
void slicer_checkpoint(const void* tf);

// Restores from a checkpoint.
// This function must be called at initialization time, and only once.
void slicer_restore(uintptr_t kstack_top);

#endif
