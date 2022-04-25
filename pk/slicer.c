// See LICENSE for license details.

#include "slicer.h"
#include "pk.h"
#include "file.h"
#include "frontend.h"
#include "syscall.h"
#include "mmap.h"
#include "boot.h"
#include "fp_emulation.h"
#include "mcall.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>

// Macros in fcntl.h.
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_CREAT     00000100
#define O_TRUNC     00001000
#define O_DIRECTORY 00200000
#define F_GETFL     3

size_t checkpoint_interval; // set by -c flag, milliseconds
const char* checkpoint_dir; // set by -d flag
int compress_mem_dump; // set by --compress flag
const char* restore_dir; // set by -r flag

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

// Opens a file at the checkpoint directory, or panics if it fails.
static inline int open_assert(const char* path, int flag)
{
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

// Returns the endianness of the current machine, 0 for little endian, 1 for big endian.
static inline int get_endianness()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return 0;
#else
  return 1;
#endif
}

// Traces system calls and dumps them to the trace file.
static void trace_syscall(const trapframe_t* tf)
{
  strace_t strace;
  for (size_t i = 0; i < 6; i++)
    strace.args[i] = tf->gpr[10 + i];
  strace.args[6] = tf->gpr[17];
  strace.epc = tf->epc;
  write_assert(syscall_trace_fd, &strace, sizeof(strace));
}

// Dumps platform information.
static void dump_platinfo()
{
  platinfo_t platinfo = {
    .magic = {'p', 'i'},
    .endian = get_endianness(),
    .ptr_size = sizeof(void*),
    .page_size = RISCV_PGSIZE,
    .major = PLATINFO_MAJOR,
    .minor = PLATINFO_MINOR,
  };
  int fd = openw_assert("platinfo");
  write_assert(fd, &platinfo, sizeof(platinfo));
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
  int fd = openw_assert("current");
  write_assert(fd, &cur, sizeof(cur));
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
  int fd = openw_assert("counter");
  write_assert(fd, &counter, sizeof(counter));
  sys_close(fd);
}

// Dumps trapframe.
static void dump_trapframe(const trapframe_t* tf)
{
  int fd = openw_assert("tf");
  write_assert(fd, tf, sizeof(*tf));
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

  int fd = openw_assert("fpregs");
  write_assert(fd, &fpregs, sizeof(fpregs));
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
  int fd = openw_assert(dump_path);
  kfd_t data = {
    .offset = sys_lseek(kfd, 0, SEEK_CUR),
    .flags = sys_fcntl(kfd, F_GETFL, 0),
    .path_len = path_len,
  };
  write_assert(fd, &data, sizeof(data));
  write_assert(fd, path_buf, path_len);
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
  int obj = openw_assert("file/obj");
  length = MAX_FILES;
  write_assert(obj, &length, sizeof(length));
  for (size_t i = 0; i < MAX_FILES; i++) {
    if (files[i].refcnt) {
      dump_kfd(&files[i]);
      index = files[i].kfd;
    } else {
      index = -1;
    }
    write_assert(obj, &index, sizeof(index));
  }
  sys_close(obj);

  // dump file descriptors
  int fd = openw_assert("file/fd");
  length = MAX_FDS;
  write_assert(fd, &length, sizeof(length));
  for (size_t i = 0; i < MAX_FDS; i++) {
    index = file_index(fds[i]);
    write_assert(fd, &index, sizeof(index));
  }
  sys_close(fd);
}

// Dumps page.
static void dump_page(uintptr_t vaddr, const pte_t* pte, const void* page)
{
  write_assert(page_file, page, RISCV_PGSIZE);
  map_record_t record = {
    .vaddr = vaddr | (*pte & ((1 << PTE_PPN_SHIFT) - 1)),
    .id = page_index++,
  };
  write_assert(pmap_file, &record, sizeof(record));
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
  write_assert(vmr_file, &data, sizeof(data));

  return vmrs_count - 1;
}

// Dumps VMR.
static void dump_vmr(uintptr_t vaddr, const vmr_t* vmr)
{
  map_record_t record = {
    .vaddr = vaddr,
    .id = vmr_insert(vmr),
  };
  write_assert(vmap_file, &record, sizeof(record));
}

// Dumps page and VMR.
static void dump_page_vmr(uintptr_t vaddr, pte_t* pte, const void* p, int is_vmr)
{
  if (is_vmr)
    dump_vmr(vaddr, p);
  else
    dump_page(vaddr, pte, p);
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
  page_file = openw_assert("mem/page");
  vmr_file = openw_assert("mem/vmr");
  pmap_file = openw_assert("mem/pmap");
  vmap_file = openw_assert("mem/vmap");

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
  kassert(CLOCK_FREQ % 1000 == 0);
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
  syscall_trace_fd = openw_assert("strace");
}

void slicer_syscall_handler(const void* tf)
{
  // skip if checkpointing is disabled
  if (!checkpoint_interval) return;

  // trace system call
  trace_syscall((const trapframe_t*)tf);

  // perform checkpoint
  if ((rdcycle64() - last_checkpoint_cycle) / (CLOCK_FREQ / 10000) >= checkpoint_interval) {
    do_checkpoint((const trapframe_t*)tf);
    last_checkpoint_cycle = rdcycle64();

    // TODO: remove
    panic("checkpointed");
  }
}

// Sets performance counters.
static inline void set_counter(uint64_t time, uint64_t cycle, uint64_t instret)
{
  register size_t a7 asm("a7") = SBI_FEXT_SET_COUNTER;
#if __riscv_xlen == 32
  register uint32_t a0 asm("a0") = time & 0xffffffff;
  register uint32_t a1 asm("a1") = time >> 32;
  register uint32_t a2 asm("a2") = cycle & 0xffffffff;
  register uint32_t a3 asm("a3") = cycle >> 32;
  register uint32_t a4 asm("a4") = instret & 0xffffffff;
  register uint32_t a5 asm("a5") = instret >> 32;
  asm volatile("ecall\n\t"
               : "+r"(a0)
               : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
               : "memory");
#else
  register uint64_t a0 asm("a0") = time;
  register uint64_t a1 asm("a1") = cycle;
  register uint64_t a2 asm("a2") = instret;
  asm volatile("ecall\n\t" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2) : "memory");
#endif
}

// Checks platform information, returns true if the platform is supported.
static bool check_platinfo()
{
  platinfo_t platinfo;
  int fd = openr_assert("platinfo");
  read_assert(fd, &platinfo, sizeof(platinfo));
  sys_close(fd);

  if (platinfo.magic[0] != 'p' || platinfo.magic[1] != 'i')
    return false;
  if (platinfo.endian != get_endianness())
    return false;
  if (platinfo.ptr_size != sizeof(void*))
    return false;
  if (platinfo.page_size != RISCV_PGSIZE)
    return false;
  if (platinfo.major > PLATINFO_MAJOR || platinfo.minor > PLATINFO_MINOR)
    return false;
  return true;
}

// Restores current executable's information.
static void restore_current()
{
  current_t cur;
  int fd = openr_assert("current");
  read_assert(fd, &cur, sizeof(cur));
  sys_close(fd);

  current.phent = cur.phent;
  current.phnum = cur.phnum;
  current.is_supervisor = cur.is_supervisor;
  current.phdr = cur.phdr;
  current.phdr_size = cur.phdr_size;
  current.bias = cur.bias;
  current.entry = cur.entry;
  current.brk_min = cur.brk_min;
  current.brk = cur.brk;
  current.brk_max = cur.brk_max;
  current.mmap_max = cur.mmap_max;
  current.stack_top = cur.stack_top;
  current.vm_alloc_guess = cur.vm_alloc_guess;
}

// Restores performance counters.
static void restore_counter()
{
  counter_t counter;
  int fd = openr_assert("counter");
  read_assert(fd, &counter, sizeof(counter));
  sys_close(fd);

  set_counter(counter.time, counter.cycle, counter.instret);
  if (current.cycle0) {
    current.time0 = counter.time;
    current.cycle0 = counter.cycle;
    current.instret0 = counter.instret;
  }
}

// Restores trapframe.
static void restore_trapframe(trapframe_t* tf)
{
  int fd = openr_assert("tf");
  read_assert(fd, tf, sizeof(*tf));
  sys_close(fd);
}

// Restores floating point registers.
static void restore_fpregs()
{
  fpregs_t fpregs;
  int fd = openr_assert("fpregs");
  read_assert(fd, &fpregs, sizeof(fpregs));
  sys_close(fd);

#ifdef __riscv_flen
# if __riscv_flen == 32
#   define set_fp_reg(i, v) SET_F32_REG((i) << 3, 3, 0, (v))
# else
#   define set_fp_reg(i, v) SET_F64_REG((i) << 3, 3, 0, (v))
# endif

  if (fpregs.status) {
    for (size_t i = 0; i < 32; i++)
      set_fp_reg(i, fpregs.regs[i]);
    write_csr(fcsr, fpregs.fcsr);
  }

# undef set_fp_reg
#endif

  size_t sstatus = read_csr(sstatus);
  sstatus = (sstatus & ~SSTATUS_FS) | ((fpregs.status << 13) & SSTATUS_FS);
  write_csr(sstatus, sstatus);
}

void slicer_restore(uintptr_t kstack_top)
{
  // initialize restore directory
  dir_fd = sys_openat(AT_FDCWD, restore_dir, O_DIRECTORY, 0);
  if (dir_fd < 0)
    panic("failed to open checkpoint directory: %s", restore_dir);

  // restore global information
  if (!check_platinfo())
    panic("invalid checkpoint, platform information mismatch");
  restore_current();
  restore_counter();
  trapframe_t tf;
  restore_trapframe(&tf);
  restore_fpregs();

  // TODO: system call trace

  // TODO
  panic("`slicer_restore` is not implemented");
}
