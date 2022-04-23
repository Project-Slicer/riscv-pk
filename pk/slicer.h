// See LICENSE for license details.

#ifndef _PK_SLICER_H
#define _PK_SLICER_H

#include <stddef.h>

extern size_t checkpoint_interval;
extern const char* checkpoint_dir;
extern int compress_mem_dump;
extern const char* restore_file;

void slicer_init();
void slicer_syscall_handler(const void* tf);
void slicer_restore(uintptr_t kstack_top);

#endif
