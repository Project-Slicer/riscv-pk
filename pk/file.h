// See LICENSE for license details.

#ifndef _FILE_H
#define _FILE_H

#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

typedef struct file
{
  int kfd; // file descriptor on the host side of the HTIF
  uint32_t refcnt;
} file_t;

#define MAX_FDS 128
#define MAX_FILES 128
extern file_t* fds[];
extern file_t files[];

file_t* file_get(int fd);
file_t* file_open(const char* fn, int flags, int mode);
void file_decref(file_t*);
void file_incref(file_t*);
int file_dup(file_t*);
int file_dup3(file_t*, int newfd);

file_t* file_openat(int dirfd, const char* fn, int flags, int mode);
ssize_t file_pwrite(file_t* f, const void* buf, size_t n, off_t off);
ssize_t file_pread(file_t* f, void* buf, size_t n, off_t off);
ssize_t file_write(file_t* f, const void* buf, size_t n);
ssize_t file_read(file_t* f, void* buf, size_t n);
ssize_t file_lseek(file_t* f, size_t ptr, int dir);
int file_truncate(file_t* f, off_t len);
int fd_close(int fd);

void file_init();

#endif
