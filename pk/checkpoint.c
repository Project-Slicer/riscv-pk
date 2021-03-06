// See LICENSE for license details.

#include "checkpoint.h"
#include "mmap.h"
#include "frontend.h"
#include "pk.h"
#include "dump.h"
#include "ksyscall.h"
#include "boot.h"
#include "slicer.h"
#include "fp_emulation.h"
#include "mcall.h"
#include "uncompress.h"
#include <sys/param.h>
#include <string.h>
#include <stdbool.h>

// For kernel file descriptor dump.
static char kfd_path[128];
static char kfd_dump_path[sizeof("file/kfd/0123456789")];

// For memory dump.
static int page_file, vmr_file, pmap_file, vmap_file;
#define MAX_VMRS 128
static vmr_t const* vmrs[MAX_VMRS];
static size_t vmrs_count;
static size_t bytes_written, vaddr_type;
static uintptr_t current_page;

// Copies between two file descriptors, or panics if it fails.
static void copy_assert(int dst_fd, int src_fd)
{
  struct frontend_stat st;
  if (sys_fstat(src_fd, &st) < 0)
    panic("failed to fstat: %d", src_fd);
  off_t offset = 0;
  while (offset < st.size) {
    ssize_t len = sys_sendfile(dst_fd, src_fd, &offset, st.size - offset);
    if (len < 0)
      panic("failed to sendfile: %d", src_fd);
  }
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
  close_assert(fd);
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
  close_assert(fd);
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
  close_assert(fd);
}

// Dumps trapframe.
static void dump_trapframe(const trapframe_t* tf)
{
  int fd = openw_assert("tf");
  write_assert(fd, tf, sizeof(*tf));
  close_assert(fd);
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
  close_assert(fd);
}

// Returns the index of the given file object, or -1 if the file object is NULL.
static inline uint32_t file_index(file_t* file)
{
  return file ? (uint32_t)(file - files) : -1;
}

// Gets kfd dump path by the given kfd.
static const char *get_kfd_dump_path(int kfd)
{
  // get path of the kfd dump file
  int ret = snprintf(kfd_dump_path, sizeof(kfd_dump_path), "file/kfd/%d", kfd);
  if (ret < 0 || (size_t)ret >= sizeof(kfd_dump_path))
    panic("failed to get path of kfd dump file");
  return kfd_dump_path;
}

// Checks if the given path represents a device file.
static bool is_dev_file(const char* path, size_t len)
{
  const char dev[] = "/dev/";
  if (len < sizeof(dev) - 1)
    return false;
  return memcmp(path, dev, sizeof(dev) - 1) == 0;
}

// Generates null-terminated path string of the file content dump file,
// returns length of the path, panic if failed.
static size_t gen_file_dump_path(int kfd, char* buf, size_t path_len, size_t buf_len)
{
  // get start index of the file name
  size_t file_name_index = path_len;
  while (file_name_index > 0 && kfd_path[file_name_index - 1] != '/')
    file_name_index--;
  size_t file_name_len = path_len - file_name_index;
  
  // move file name to free space for the prefix
  const char prefix[] = "file/kfd/";
  const size_t prefix_len = sizeof(prefix) - 1;
  if (file_name_len + prefix_len >= buf_len)
    panic("failed to generate file dump path");
  memmove(buf + prefix_len, buf + file_name_index, file_name_len);

  // copy prefix
  memcpy(buf, prefix, prefix_len);

  // append kfd
  int ret = snprintf(buf + prefix_len + file_name_len,
                     buf_len - prefix_len - file_name_len, ".%d", kfd);
  if (ret < 0 || (size_t)ret >= buf_len - prefix_len - file_name_len)
    panic("failed to generate file dump path");
  
  return prefix_len + file_name_len + ret;
}

// Dumps kernel file descriptor.
static void dump_kfd(int kfd)
{
  // get path of the kfd
  uint32_t path_len = getfdpath_assert(kfd, kfd_path, sizeof(kfd_path));
  if (is_dev_file(kfd_path, path_len))
    return;

  int flags = sys_fcntl(kfd, F_GETFL, 0);
  if (dump_file_contents) {
    // generate path of the file content dump file
    path_len = gen_file_dump_path(kfd, kfd_path, path_len, sizeof(kfd_path));

    // copy the content of kfd if it was opened for reading
    int out_fd = openw_assert(kfd_path);
    if ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR)
      copy_assert(out_fd, kfd);
    close_assert(out_fd);
  }

  // dump kfd data
  int fd = openw_assert(get_kfd_dump_path(kfd));
  kfd_t data = {
    .offset = sys_lseek(kfd, 0, SEEK_CUR),
    .flags = flags,
    .path_len = path_len,
  };
  write_assert(fd, &data, sizeof(data));
  write_assert(fd, kfd_path, path_len);
  close_assert(fd);
}

// Dumps file objects.
static void dump_files()
{
  mkdir_assert("file");
  mkdir_assert("file/kfd");
  uint32_t length, index;

  // dump file object data
  int obj = openw_assert("file/obj");
  length = MAX_FILES;
  write_assert(obj, &length, sizeof(length));
  for (size_t i = 0; i < MAX_FILES; i++) {
    if (files[i].refcnt)
      dump_kfd(files[i].kfd);
    write_assert(obj, &files[i].kfd, sizeof(files[i].kfd));
    write_assert(obj, &files[i].refcnt, sizeof(files[i].refcnt));
  }
  close_assert(obj);

  // dump file descriptors
  int fd = openw_assert("file/fd");
  length = MAX_FDS;
  write_assert(fd, &length, sizeof(length));
  for (size_t i = 0; i < MAX_FDS; i++) {
    index = file_index(fds[i]);
    write_assert(fd, &index, sizeof(index));
  }
  close_assert(fd);
}

// Dumps page.
static void dump_page(uintptr_t vaddr, const pte_t* pte, const void* page)
{
  write_assert(page_file, page, RISCV_PGSIZE);
  size_t vaddr_type = vaddr | (*pte & ((1 << PTE_PPN_SHIFT) - 1));
  write_assert(pmap_file, &vaddr_type, sizeof(vaddr_type));
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
    .refcnt = vmr->refcnt,
  };
  write_assert(vmr_file, &data, sizeof(data));

  return vmrs_count - 1;
}

// Dumps VMR.
static void dump_vmr(uintptr_t vaddr, const vmr_t* vmr)
{
  vmap_record_t record = {
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
  vmrs_count = 0;
  write_assert(page_file, "", 1);
  dump_page_table(dump_page_vmr);

  // close files
  close_assert(page_file);
  close_assert(vmr_file);
  close_assert(pmap_file);
  close_assert(vmap_file);
}

void do_checkpoint(const void* tf)
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
  close_assert(fd);

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
  close_assert(fd);

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
  close_assert(fd);

  set_counter(counter.time, counter.cycle, counter.instret);
  if (current.cycle0) {
    // read counters again in case `set_counter` has no effect
    current.time0 = rdtime64();
    current.cycle0 = rdcycle64();
    current.instret0 = rdinstret64();
  }
}

// Restores trapframe.
static void restore_trapframe(trapframe_t* tf)
{
  int fd = openr_assert("tf");
  read_assert(fd, tf, sizeof(*tf));
  close_assert(fd);
}

// Restores floating point registers.
static void restore_fpregs()
{
  fpregs_t fpregs;
  int fd = openr_assert("fpregs");
  read_assert(fd, &fpregs, sizeof(fpregs));
  close_assert(fd);

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

// Restores kernel file descriptor.
static int restore_kfd(int kfd)
{
  extern int dir_fd;
  int fd = sys_openat(dir_fd, get_kfd_dump_path(kfd), O_RDONLY, 0);
  if (fd < 0) {
    // must be stdin, stdout, or stderr
    kassert(kfd >= 0 && kfd <= 2);
    return kfd;
  }

  kfd_t data;
  read_assert(fd, &data, sizeof(data));
  read_assert(fd, kfd_path, data.path_len);
  close_assert(fd);

  kfd_path[data.path_len] = '\0';
  int new_kfd = open_assert(kfd_path, data.flags);
  sys_lseek(new_kfd, data.offset, SEEK_SET);
  return new_kfd;
}

// Restores file objects.
static void restore_files()
{
  uint32_t length, index;

  // restore file object data
  int obj = openr_assert("file/obj");
  read_assert(obj, &length, sizeof(length));
  if (length > MAX_FILES)
    panic("file object array length exceeds MAX_FILES");
  for (size_t i = 0; i < length; i++) {
    read_assert(obj, &files[i].kfd, sizeof(files[i].kfd));
    read_assert(obj, &files[i].refcnt, sizeof(files[i].refcnt));
    if (files[i].refcnt)
      files[i].kfd = restore_kfd(files[i].kfd);
  }
  close_assert(obj);

  // restore file descriptors
  int fd = openr_assert("file/fd");
  read_assert(fd, &length, sizeof(length));
  if (length > MAX_FDS)
    panic("file descriptor array length exceeds MAX_FDS");
  for (size_t i = 0; i < length; i++) {
    read_assert(fd, &index, sizeof(index));
    if (index == -1)
      continue;
    if (index >= MAX_FILES)
      panic("invalid file object index");
    fds[i] = &files[index];
  }
  close_assert(fd);
}

// Inserts the current page into the page table.
static void insert_current_page()
{
  uintptr_t vaddr = vaddr_type & ~(RISCV_PGSIZE - 1);
  int type = vaddr_type & ((1 << PTE_PPN_SHIFT) - 1);
  insert_page(vaddr, current_page, type);
}

// For uncompressing memory dump.
static void write_page(uint8_t byte)
{
  if (bytes_written == 0) {
    read_assert(pmap_file, &vaddr_type, sizeof(vaddr_type));
    current_page = __page_alloc_assert();
  }
  ((uint8_t*)pa2kva(current_page))[bytes_written++] = byte;
  if (bytes_written == RISCV_PGSIZE) {
    insert_current_page();
    bytes_written = 0;
  }
}

// Restores pages.
static void restore_pages()
{
  pmap_file = openr_assert("mem/pmap");
  page_file = openr_assert("mem/page");

  // check if the page dump was compressed
  uint8_t compressed;
  read_assert(page_file, &compressed, sizeof(compressed));
  if (compressed) {
    bytes_written = 0;
    if (uncompress(page_file, write_page) != 0)
      panic("failed to uncompress page dump");
  } else {
    ssize_t n;
    while ((n = sys_read(pmap_file, &vaddr_type, sizeof(vaddr_type))) ==
           sizeof(vaddr_type)) {
      current_page = __page_alloc_assert();
      read_assert(page_file, (void*)pa2kva(current_page), RISCV_PGSIZE);
      insert_current_page();
    }
    if (n != 0)
      panic("failed to read physical memory map");
  }

  close_assert(pmap_file);
  close_assert(page_file);
}

// Restores VMRs.
static void restore_vmrs()
{
  int vmr_fd = openr_assert("mem/vmr");

  vmrs_count = 0;
  for (;;) {
    vmr_data_t data;
    ssize_t n = sys_read(vmr_fd, &data, sizeof(data));
    if (n < 0)
      panic("failed to read VMR object");
    if (n == 0)
      break;

    file_t* file;
    if (data.file == -1) {
      file = NULL;
    } else if (data.file >= MAX_FILES) {
      panic("invalid file object index");
    } else {
      file = &files[data.file];
    }
    vmrs[vmrs_count++] = new_vmr(data.addr, data.length, file, data.offset,
                                 data.refcnt, data.prot);
  }

  close_assert(vmr_fd);
}

// Restores VMR mapping.
static void restore_vmr_map()
{
  int vmap_fd = openr_assert("mem/vmap");

  for (;;) {
    vmap_record_t record;
    ssize_t n = sys_read(vmap_fd, &record, sizeof(record));
    if (n < 0)
      panic("failed to read VMR mapping");
    if (n == 0)
      break;

    if (record.id >= vmrs_count)
      panic("invalid VMR object index");
    insert_vmr(record.vaddr, vmrs[record.id]);
  }

  close_assert(vmap_fd);
}

// Restores memory.
static void restore_memory()
{
  restore_pages();
  restore_vmrs();
  restore_vmr_map();
}

void do_restore(void* tf)
{
  // restore global information
  if (!check_platinfo())
    panic("invalid checkpoint, platform information mismatch");
  restore_current();
  restore_counter();
  restore_trapframe(tf);
  restore_fpregs();
  // restore file objects
  restore_files();
  // restore memory
  restore_memory();
}
