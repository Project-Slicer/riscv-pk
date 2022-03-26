// See LICENSE for license details.

#ifndef _PK_SLICER_H
#define _PK_SLICER_H

#include <stddef.h>

extern size_t checkpoint_interval;
extern const char *checkpoint_dir;

void slicer_init();
void slicer_syscall_handler(const void* tf);

#endif
