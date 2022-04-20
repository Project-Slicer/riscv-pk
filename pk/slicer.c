// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "file.h"
#include "frontend.h"
#include "syscall.h"
#include "mmap.h"
#include "boot.h"
#include "fp_emulation.h"
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>

size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
int compress_mem_dump; // set by --compress flag
const char* restore_file; // set by -r flag

static uint64_t last_checkpoint_cycle;
static int dir_fd, syscall_trace_fd;

// System call trace record.
typedef struct {
  size_t args[7];
  size_t epc;
} strace_t;

// Platform version.
#define PLATINFO_MAJOR 0
#define PLATINFO_MINOR 1

// Platform information.
typedef struct {
  uint8_t magic[2];
  uint8_t endian;
  uint8_t ptr_size;
  uint32_t page_size;
  uint16_t major;
  uint16_t minor;
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

// Floating point registers.
typedef struct {
  uint32_t status;
  uint32_t fcsr;
  uint64_t regs[32];
} fpregs_t;

// Kernel file descriptor data.
typedef struct {
  uint64_t offset;
  uint32_t flags;
  uint32_t path_len;
} kfd_t;

// For kernel file descriptor dump.
static bool kfd_visited[MAX_FILES];
static char path_buf[PATH_MAX];

// VMR object data.
typedef struct {
  size_t addr;
  size_t length;
  size_t offset;
  uint32_t file;
  uint32_t prot;
} vmr_data_t;

// Physical/VMR mapping record.
typedef struct {
  size_t vaddr;
  size_t id;
} map_record_t;

// For memory dump.
static int page_file, vmr_file, pmap_file, vmap_file;
static size_t page_index;
#define MAX_VMRS 128
static vmr_t const* vmrs[MAX_VMRS];
static size_t vmrs_count;

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

// Opens and creates a write-only file at the checkpoint directory, or panics if it fails.
static inline int open_assert(const char* path)
{
  int fd = sys_openat(dir_fd, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    panic("failed to open: %s", path);
  return fd;
}

// Creates a directory at the checkpoint directory if it does not exist, or panics if it fails.
static inline void mkdir_assert(const char* path)
{
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

// Traces system calls and dumps them to the trace file.
static void trace_syscall(const trapframe_t* tf)
{
  strace_t strace;
  for (size_t i = 0; i < 6; i++)
    strace.args[i] = tf->gpr[10 + i];
  strace.args[6] = tf->gpr[17];
  strace.epc = tf->epc;
  sys_write(syscall_trace_fd, &strace, sizeof(strace));
}

// Dumps platform information.
static void dump_platinfo()
{
  platinfo_t platinfo = {
    .magic = {'p', 'i'},
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    .endian = 0,
#else
    .endian = 1,
#endif
    .ptr_size = sizeof(void*),
    .page_size = RISCV_PGSIZE,
    .major = PLATINFO_MAJOR,
    .minor = PLATINFO_MINOR,
  };
  int fd = open_assert("platinfo");
  sys_write(fd, &platinfo, sizeof(platinfo));
  sys_close(fd);
}

// Dumps current executable's information.
static void dump_current()
{
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
  sys_write(fd, &cur, sizeof(cur));
  sys_close(fd);
}

// Dumps performance counters.
static void dump_counter()
{
  counter_t counter = {
    .time = rdtime64(),
    .cycle = rdcycle64(),
    .instret = rdinstret64(),
  };
  int fd = open_assert("counter");
  sys_write(fd, &counter, sizeof(counter));
  sys_close(fd);
}

// Dumps trapframe.
static void dump_trapframe(const trapframe_t* tf)
{
  int fd = open_assert("tf");
  sys_write(fd, tf, sizeof(*tf));
  sys_close(fd);
}

// Dumps floating point registers.
static void dump_fpregs()
{
  fpregs_t fpregs;
  fpregs.status = (read_csr(sstatus) & SSTATUS_FS) >> 13;

#ifdef __riscv_flen
# if __riscv_flen == 32
#   define get_fp_reg(i) GET_F32_REG((i) << 3, 3, 0)
# else
#   define get_fp_reg(i) GET_F64_REG((i) << 3, 3, 0)
# endif

  if (fpregs.status) {
    fpregs.fcsr = read_csr(fcsr);
    for (size_t i = 0; i < 32; i++)
      fpregs.regs[i] = get_fp_reg(i);
  }

# undef get_fp_reg
#endif

  int fd = open_assert("fpregs");
  sys_write(fd, &fpregs, sizeof(fpregs));
  sys_close(fd);
}

// Returns the index of the given file object, or -1 if the file object is NULL.
static inline uint32_t file_index(file_t* file)
{
  return file ? (uint32_t)(file - files) : -1;
}

// Checks if the given path represents a device file.
static bool is_dev_file(const char* path, size_t len)
{
  const char dev[] = "/dev/";
  if (len >= sizeof(dev) - 1)
    for (size_t i = 0; i < sizeof(dev) - 1; i++)
      if (path_buf[i] != dev[i])
        return false;
  return true;
}

// Dumps kernel file descriptor.
static void dump_kfd(file_t* file)
{
  // check if the kfd has already been dumped
  uint32_t index = file_index(file);
  if (kfd_visited[index])
    return;
  kfd_visited[index] = true;
  int kfd = file->kfd;

  // get path of the kfd dump file
  char dump_path[sizeof("file/kfd/0123456789")];
  int ret = snprintf(dump_path, sizeof(dump_path), "file/kfd/%d", kfd);
  if (ret < 0 || (size_t)ret >= sizeof(dump_path))
    panic("failed to get path of kfd dump file");

  // get path of the kfd
  uint32_t path_len = getfdpath_assert(kfd, path_buf, sizeof(path_buf));
  if (is_dev_file(path_buf, path_len))
    return;

  // dump kfd data
  int fd = open_assert(dump_path);
  kfd_t data = {
    .offset = sys_lseek(kfd, 0, SEEK_CUR),
    .flags = sys_fcntl(kfd, F_GETFL, 0),
    .path_len = path_len,
  };
  sys_write(fd, &data, sizeof(data));
  sys_write(fd, path_buf, path_len);
  sys_close(fd);
}

// Dumps file objects.
static void dump_files()
{
  mkdir_assert("file");
  mkdir_assert("file/kfd");
  memset(kfd_visited, 0, sizeof(kfd_visited));
  uint32_t length, index;

  // dump file object data
  int obj = open_assert("file/obj");
  length = MAX_FILES;
  sys_write(obj, &length, sizeof(length));
  for (size_t i = 0; i < MAX_FILES; i++) {
    if (files[i].refcnt) {
      dump_kfd(&files[i]);
      index = files[i].kfd;
    } else {
      index = -1;
    }
    sys_write(obj, &index, sizeof(index));
  }
  sys_close(obj);

  // dump file descriptors
  int fd = open_assert("file/fd");
  length = MAX_FDS;
  sys_write(fd, &length, sizeof(length));
  for (size_t i = 0; i < MAX_FDS; i++) {
    index = file_index(fds[i]);
    sys_write(fd, &index, sizeof(index));
  }
  sys_close(fd);
}

// Dumps page.
static void dump_page(uintptr_t vaddr, const void* page)
{
  sys_write(page_file, page, RISCV_PGSIZE);
  map_record_t record = {
    .vaddr = vaddr,
    .id = page_index++,
  };
  sys_write(pmap_file, &record, sizeof(record));
}

// Inserts the given VMR object to the VMR list, returns the index of the VMR object.
static size_t vmr_insert(const vmr_t* vmr)
{
  for (size_t count = vmrs_count; count > 0; count--) {
    size_t index = count - 1;
    if (vmrs[index] == vmr)
      return index;
  }
  if (vmrs_count == MAX_VMRS)
    panic("VMR list length exceeded");
  vmrs[vmrs_count++] = vmr;

  // dump to file
  vmr_data_t data = {
    .addr = vmr->addr,
    .length = vmr->length,
    .offset = vmr->offset,
    .file = file_index(vmr->file),
    .prot = vmr->prot,
  };
  sys_write(vmr_file, &data, sizeof(data));

  return vmrs_count - 1;
}

// Dumps VMR.
static void dump_vmr(uintptr_t vaddr, const vmr_t* vmr)
{
  map_record_t record = {
    .vaddr = vaddr,
    .id = vmr_insert(vmr),
  };
  sys_write(vmap_file, &record, sizeof(record));
}

// Dumps page and VMR.
static void dump_page_vmr(uintptr_t vaddr, pte_t* pte, const void* p, int is_vmr)
{
  if (is_vmr)
    dump_vmr(vaddr, p);
  else
    dump_page(vaddr, p);
}

// Clears the A-bit and D-bit of the page table entry.
static void clear_ad(uintptr_t vaddr, pte_t* pte, const void* p, int is_vmr)
{
  if (!is_vmr) {
    *pte &= ~(PTE_A | PTE_D);
    flush_tlb_entry(vaddr);
  }
}

// Dumps memory.
static void dump_memory()
{
  // create files
  mkdir_assert("mem");
  page_file = open_assert("mem/page");
  vmr_file = open_assert("mem/vmr");
  pmap_file = open_assert("mem/pmap");
  vmap_file = open_assert("mem/vmap");

  // dump pages and VMRs
  page_index = vmrs_count = 0;
  dump_page_table(dump_page_vmr);
  // clear A-bit and D-bit of page table entries
  dump_page_table(clear_ad);

  // close files
  sys_close(page_file);
  sys_close(vmr_file);
  sys_close(pmap_file);
  sys_close(vmap_file);
}

// Performs checkpoint operation.
static void do_checkpoint(const trapframe_t* tf)
{
  // dump global information
  dump_platinfo();
  dump_current();
  dump_counter();
  dump_trapframe(tf);
  dump_fpregs();
  // dump file objects
  dump_files();
  // dump memory
  dump_memory();
}

void slicer_init()
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // initialize cycle counter
  last_checkpoint_cycle = rdcycle64();

  // initialize checkpoint directory
  if (checkpoint_dir) {
    dir_fd = sys_openat(AT_FDCWD, checkpoint_dir, O_DIRECTORY, 0);
    if (dir_fd < 0)
      panic("failed to open checkpoint directory: %s", checkpoint_dir);
  } else {
    dir_fd = AT_FDCWD;
  }

  // initialize syscall trace file
  syscall_trace_fd = open_assert("strace");
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

    // TODO: remove
    panic("checkpointed");
  }
}
