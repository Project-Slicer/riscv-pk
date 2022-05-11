// See LICENSE for license details.

#ifndef _PK_KSYSCALL_H
#define _PK_KSYSCALL_H

#include "frontend.h"
#include "mmap.h"
#include "pk.h"
#include <string.h>

// Macros in fcntl.h.
#define O_ACCMODE   00000003
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002
#define O_CREAT     00000100
#define O_TRUNC     00001000
#define O_DIRECTORY 00200000
#define F_GETFL     3

// Wrapper of system call `openat`.
static inline int sys_openat(int dir_fd, const char* path, int flags, mode_t mode)
{
  size_t path_size = strlen(path) + 1;
  return frontend_syscall(SYS_openat, dir_fd, kva2pa(path), path_size, flags, mode, 0, 0);
}

// Wrapper of system call `write`.
static inline ssize_t sys_write(int fd, const void* buf, size_t count)
{
  return frontend_syscall(SYS_write, fd, kva2pa(buf), count, 0, 0, 0, 0);
}

// Wrapper of system call `read`.
static inline ssize_t sys_read(int fd, void* buf, size_t count)
{
  return frontend_syscall(SYS_read, fd, kva2pa(buf), count, 0, 0, 0, 0);
}

// Wrapper of system call `close`.
static inline int sys_close(int fd)
{
  return frontend_syscall(SYS_close, fd, 0, 0, 0, 0, 0, 0);
}

// Wrapper of system call `fstatat`.
static inline int sys_fstatat(int dir_fd, const char* path, struct frontend_stat* st, int flags)
{
  size_t path_size = strlen(path) + 1;
  return frontend_syscall(SYS_fstatat, dir_fd, kva2pa(path), path_size, kva2pa(st), flags, 0, 0);
}

// Wrapper of system call `mkdirat`.
static inline int sys_mkdirat(int dir_fd, const char* path, mode_t mode)
{
  size_t path_size = strlen(path) + 1;
  return frontend_syscall(SYS_mkdirat, dir_fd, kva2pa(path), path_size, mode, 0, 0, 0);
}

// Wrapper of system call `lseek`.
static inline ssize_t sys_lseek(int fd, size_t offset, int whence)
{
  return frontend_syscall(SYS_lseek, fd, offset, whence, 0, 0, 0, 0);
}

// Wrapper of system call `fcntl`.
static inline int sys_fcntl(int fd, int cmd, int arg)
{
  return frontend_syscall(SYS_fcntl, fd, cmd, arg, 0, 0, 0, 0);
}

// Wrapper of system call `sendfile`.
static inline ssize_t sys_sendfile(int out_fd, int in_fd, off_t* offset, size_t count)
{
  return frontend_syscall(SYS_sendfile, out_fd, in_fd, kva2pa(offset), count, 0, 0, 0);
}

// Wrapper of system call `fstat`.
static inline int sys_fstat(int fd, struct frontend_stat* st)
{
  return frontend_syscall(SYS_fstat, fd, kva2pa(st), 0, 0, 0, 0, 0);
}

// Wrapper of system call `renameat`.
static inline int sys_renameat(int old_dir_fd, const char* old_path,
                               int new_dir_fd, const char* new_path)
{
  size_t old_path_size = strlen(old_path) + 1;
  size_t new_path_size = strlen(new_path) + 1;
  return frontend_syscall(SYS_renameat, old_dir_fd, kva2pa(old_path),
                          old_path_size, new_dir_fd, kva2pa(new_path),
                          new_path_size, 0);
}

// Wrapper of system call `pwrite`.
static inline ssize_t sys_pwrite(int fd, const void* buf, size_t count, off_t offset)
{
  return frontend_syscall(SYS_pwrite, fd, kva2pa(buf), count, offset, 0, 0, 0);
}

// Opens a file at the checkpoint directory, or panics if it fails.
static inline int open_assert(const char* path, int flag)
{
  extern int dir_fd;
  int fd = sys_openat(dir_fd, path, flag, 0644);
  if (fd < 0)
    panic("failed to open: %s", path);
  return fd;
}

// Opens a read-only file at the checkpoint directory, or panics if it fails.
static inline int openr_assert(const char* path)
{
  return open_assert(path, O_RDONLY);
}

// Opens and creates a write-only file at the checkpoint directory, or panics if it fails.
static inline int openw_assert(const char* path)
{
  return open_assert(path, O_WRONLY | O_CREAT | O_TRUNC);
}

// Creates a directory at the checkpoint directory if it does not exist, or panics if it fails.
static inline void mkdir_assert(const char* path)
{
  extern int dir_fd;
  struct frontend_stat st;
  if (sys_fstatat(dir_fd, path, &st, 0) == 0 && S_ISDIR(st.mode))
    return;
  if (sys_mkdirat(dir_fd, path, 0755) < 0)
    panic("failed to create: %s", path);
}

// Gets the path of the given file descriptor, or panics if it fails.
static inline int getfdpath_assert(int fd, char* buf, size_t size)
{
  int len = frontend_syscall(SYS_getfdpath, fd, kva2pa(buf), size, 0, 0, 0, 0);
  if (len < 0)
    panic("failed to get path of fd: %d", fd);
  return len;
}

// Writes the given buffer to the file descriptor, or panics if it fails.
static inline void write_assert(int fd, const void* buf, size_t count)
{
  ssize_t len = sys_write(fd, buf, count);
  if (len < 0 || (size_t)len != count)
    panic("failed to write to fd: %d", fd);
}

// Reads the given buffer from the file descriptor, or panics if it fails.
static inline void read_assert(int fd, void* buf, size_t count)
{
  ssize_t len = sys_read(fd, buf, count);
  if (len < 0 || (size_t)len != count)
    panic("failed to read from fd: %d", fd);
}

// Closes the given file descriptor, or panics if it fails.
static inline void close_assert(int fd)
{
  if (sys_close(fd) < 0)
    panic("failed to close fd: %d", fd);
}

#endif
