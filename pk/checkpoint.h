// See LICENSE for license details.

#ifndef _PK_CHECKPOINT_H
#define _PK_CHECKPOINT_H

// Traces system calls and dumps them to the trace file.
void trace_syscall(int strace_fd, const void* t);
// Performs checkpoint operation.
void do_checkpoint(const void* tf);
// Performs restore operation.
void do_restore(void* tf);

#endif
