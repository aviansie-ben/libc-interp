#include <iostream>
#include <sstream>

extern "C" {
  #include <fcntl.h>
  #include <time.h>
  #include <unistd.h>
}

#include "syscall.hpp"
#include "src/cast.h"

using namespace wabt::interp;

namespace wabt {

#define CHECK_TRAP(...)                    \
  do {                                     \
    interp::Result _result = (__VA_ARGS__); \
    if (_result != interp::Result::Ok) {    \
      return _result;                       \
    }                                      \
  } while (0)

#define PRIimport "\"" PRIstringview "." PRIstringview "\""
#define PRINTF_IMPORT_ARG(x)                   \
  WABT_PRINTF_STRING_VIEW_ARG((x).module_name) \
  , WABT_PRINTF_STRING_VIEW_ARG((x).field_name)

enum class SyscallNum : int {
  read = 3,
  write = 4,
  open = 5,
  close = 6,
  brk = 45,
  ioctl = 54,
  munmap = 91,
  llseek = 140,
  readv = 145,
  writev = 146,
  mremap = 163,
  mmap2 = 192,
  madvise = 219,
  exit_group = 252,
  clock_gettime = 265,
  membarrier = 375,
};

struct IoVec {
  uint32_t base;
  uint32_t len;
};

interp::HostFunc::Callback CreateSysCallback(SyscallHandler* sys) {
  return [=](const interp::HostFunc*, const interp::FuncSignature*, const TypedValues& args, TypedValues& results) {
    results[0].type = Type::I32;
    return sys->HandleSyscall(args.at(0).value.i32, args.data() + 1, args.size() - 1, &results.at(0).value.i32);
  };
}

interp::HostFunc::Callback CreateUnimplCallback(const char* name) {
  return [=](const interp::HostFunc*, const interp::FuncSignature*, const TypedValues&, TypedValues&) {
    std::cout << "call to unimplemented " << name << "\n";
    return interp::Result::TrapHostTrapped;
  };
}

void SyscallHandler::RegisterOnModule(interp::HostModule* module) {
  module->AppendFuncExport("__syscall0", {{Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall1", {{Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall2", {{Type::I32, Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall3", {{Type::I32, Type::I32, Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall4", {{Type::I32, Type::I32, Type::I32, Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall5", {{Type::I32, Type::I32, Type::I32, Type::I32, Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall6", {{Type::I32, Type::I32, Type::I32, Type::I32, Type::I32, Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall", {{Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));
  module->AppendFuncExport("__syscall_cp_asm", {{Type::I32, Type::I32, Type::I32, Type::I32, Type::I32, Type::I32, Type::I32, Type::I32}, {Type::I32}}, CreateSysCallback(this));

  module->AppendFuncExport("longjmp", {{Type::I32, Type::I32}, {}}, CreateUnimplCallback("longjmp"));
  module->AppendFuncExport("setjmp", {{Type::I32}, {Type::I32}}, CreateUnimplCallback("setjmp"));
  module->AppendFuncExport("_Unwind_RaiseException", {{Type::I32}, {Type::I32}}, CreateUnimplCallback("_Unwind_RaiseException"));
  module->AppendFuncExport("_Unwind_DeleteException", {{Type::I32}, {}}, CreateUnimplCallback("_Unwind_DeleteException"));
  module->AppendFuncExport("_Unwind_GetLanguageSpecificData", {{Type::I32}, {Type::I32}}, CreateUnimplCallback("_Unwind_GetLanguageSpecificData"));
  module->AppendFuncExport("_Unwind_GetIP", {{Type::I32}, {Type::I32}}, CreateUnimplCallback("_Unwind_GetIP"));
  module->AppendFuncExport("_Unwind_GetRegionStart", {{Type::I32}, {Type::I32}}, CreateUnimplCallback("_Unwind_GetRegionStart"));
  module->AppendFuncExport("_Unwind_SetGR", {{Type::I32, Type::I32, Type::I32}, {}}, CreateUnimplCallback("_Unwind_SetGR"));
  module->AppendFuncExport("_Unwind_SetIP", {{Type::I32, Type::I32}, {}}, CreateUnimplCallback("_Unwind_SetIP"));

  module->AppendGlobalExport("__cp_begin", false, uint32_t(0));
  module->AppendGlobalExport("__cp_end", false, uint32_t(0));
  module->AppendGlobalExport("__cp_cancel", false, uint32_t(0));
}

interp::Result SyscallHandler::HandleSyscall(int n, const interp::TypedValue* args, Index num_args, uint32_t* return_value) {
  switch (static_cast<SyscallNum>(n)) {
    case SyscallNum::read:
      if (num_args != 3) {
        std::cout << "read with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleRead(static_cast<int>(args[0].value.i32),
                         args[1].value.i32,
                         args[2].value.i32,
                         return_value);

    case SyscallNum::write:
      if (num_args != 3) {
        std::cout << "write with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleWrite(static_cast<int>(args[0].value.i32),
                         args[1].value.i32,
                         args[2].value.i32,
                         return_value);

    case SyscallNum::open:
      if (num_args != 3) {
        std::cout << "open called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleOpen(args[0].value.i32, args[1].value.i32, args[2].value.i32, return_value);

    case SyscallNum::close:
      if (num_args != 1) {
        std::cout << "close called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleClose(static_cast<int>(args[0].value.i32), return_value);

    case SyscallNum::brk:
      if (num_args != 1) {
        std::cout << "brk called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleBrk(args[0].value.i32, return_value);

    case SyscallNum::ioctl:
      if (num_args < 2) {
        std::cout << "ioctl called with too few arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleIoctl(static_cast<int>(args[0].value.i32),
                         static_cast<int>(args[1].value.i32),
                         args + 2,
                         num_args - 2,
                         return_value);

    case SyscallNum::munmap:
      if (num_args != 2) {
        std::cout << "munmap called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleMunmap(args[0].value.i32,
                          args[1].value.i32,
                          return_value);

    case SyscallNum::llseek:
      if (num_args != 5) {
        std::cout << "llseek called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleLlseek(static_cast<int>(args[0].value.i32),
                          args[1].value.i32,
                          args[2].value.i32,
                          args[3].value.i32,
                          args[4].value.i32,
                          return_value);

    case SyscallNum::readv:
      if (num_args != 3) {
        std::cout << "readv called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleReadv(static_cast<int>(args[0].value.i32),
                          args[1].value.i32,
                          args[2].value.i32,
                          return_value);

    case SyscallNum::writev:
      if (num_args != 3) {
        std::cout << "writev called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleWritev(static_cast<int>(args[0].value.i32),
                          args[1].value.i32,
                          args[2].value.i32,
                          return_value);

    case SyscallNum::mremap:
      if (num_args != 5) {
        std::cout << "mremap called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleMremap(args[0].value.i32,
                          args[1].value.i32,
                          args[2].value.i32,
                          args[3].value.i32,
                          args[4].value.i32,
                          return_value);

    case SyscallNum::mmap2:
      if (num_args != 6) {
        std::cout << "mmap2 called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleMmap(args[0].value.i32,
                        args[1].value.i32,
                        args[2].value.i32,
                        args[3].value.i32,
                        static_cast<int>(args[4].value.i32),
                        args[5].value.i32,
                        return_value);

    case SyscallNum::madvise:
      *return_value = static_cast<uint32_t>(-1);
      return interp::Result::Ok;

    case SyscallNum::exit_group:
      if (num_args != 1) {
        std::cout << "exit_group called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      std::cout << "exit_group(" << args[0].value.i32 << ") called" << std::endl;
      return interp::Result::TrapHostTrapped;

    case SyscallNum::clock_gettime:
      if (num_args != 2) {
        std::cout << "clock_gettime called with invalid arguments\n";
        return interp::Result::TrapHostTrapped;
      }

      return HandleClockGetTime(args[0].value.i32, args[1].value.i32, return_value);

    case SyscallNum::membarrier:
      *return_value = static_cast<uint32_t>(-1);
      return interp::Result::Ok;

    default:
      std::cout << "unimplemented syscall " << n << "\n";
      return interp::Result::TrapHostTrapped;
  }
}

interp::Result SyscallHandler::GetMemoryAddress(uint32_t src, uint32_t size, void** addr) {
  auto* mem = env_->GetMemory(0);
  if (src + size < src || src + size >= mem->data.size()) {
    return interp::Result::TrapMemoryAccessOutOfBounds;
  }

  *addr = mem->data.data() + src;
  return interp::Result::Ok;
}

interp::Result SyscallHandler::CopyFromMemory(void* dst, uint32_t src, uint32_t size) {
  void* src_p;

  CHECK_TRAP(GetMemoryAddress(src, size, &src_p));
  memcpy(dst, src_p, size);

  return interp::Result::Ok;
}

interp::Result SyscallHandler::StrcpyFromMemory(std::string* dst, uint32_t src) {
  auto* mem = env_->GetMemory(0);
  char* mem_end = mem->data.data() + mem->data.size();

  if (src >= mem->data.size()) {
    return interp::Result::TrapMemoryAccessOutOfBounds;
  }

  std::ostringstream dst_s;
  char* src_p = mem->data.data() + src;

  while (src_p != mem_end && *src_p != '\0') {
    dst_s << *src_p++;
  }

  if (src_p == mem_end) {
    return interp::Result::TrapMemoryAccessOutOfBounds;
  }

  *dst = dst_s.str();
  return interp::Result::Ok;
}

interp::Result SyscallHandler::CopyToMemory(const void* src, uint32_t dst, uint32_t size) {
  void* dst_p;

  CHECK_TRAP(GetMemoryAddress(dst, size, &dst_p));
  memcpy(dst_p, src, size);

  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleRead(int fd, uint32_t buf, uint32_t size, uint32_t* return_value) {
  void* buf_p;

  CHECK_TRAP(GetMemoryAddress(buf, size, &buf_p));
  *return_value = static_cast<uint32_t>(read(fd, buf_p, size));

  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleWrite(int fd, uint32_t buf, uint32_t size, uint32_t* return_value) {
  void* buf_p;

  CHECK_TRAP(GetMemoryAddress(buf, size, &buf_p));
  *return_value = static_cast<uint32_t>(write(fd, buf_p, size));

  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleOpen(uint32_t filename_addr, uint32_t flags, uint32_t mode, uint32_t* return_value) {
  std::string filename;

  CHECK_TRAP(StrcpyFromMemory(&filename, filename_addr));
  *return_value = static_cast<uint32_t>(open(filename.c_str(), static_cast<int>(flags), mode));

  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleClose(int fd, uint32_t* return_value) {
  *return_value = close(fd);
  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleBrk(uint32_t addr, uint32_t* return_value) {
  *return_value = 0;
  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleIoctl(int fd, int cmd, const interp::TypedValue* args, Index num_args, uint32_t* return_value) {
  // TODO Implement this?
  *return_value = static_cast<uint32_t>(-1);
  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleMunmap(uint32_t address, uint32_t size, uint32_t* return_value) {
  auto* mem = env_->GetMemory(0);

  if (address + size < address || address + size > mem->data.size()) {
    *return_value = static_cast<uint32_t>(-1);
    return interp::Result::Ok;
  } else if ((address & 0xfff) != 0 || (size & 0xfff) != 0) {
    *return_value = static_cast<uint32_t>(-1);
    return interp::Result::Ok;
  }

  MmapFreeRegion r;

  r.start = address;
  r.size = size;

  bool continue_coalescing = true;

  while (continue_coalescing) {
    continue_coalescing = false;

    for (auto it = mmap_free_regions_.begin(); it != mmap_free_regions_.end(); ++it) {
      auto& r2 = *it;

      if (r2.start + r2.size == address) {
        r.start = r2.start;
        r.size += r2.size;
        mmap_free_regions_.erase(it);

        continue_coalescing = true;
        break;
      } else if (r2.start == address + size) {
        r.size += r2.size;
        mmap_free_regions_.erase(it);

        continue_coalescing = true;
        break;
      }
    }
  }

  mmap_free_regions_.push_back(r);

  *return_value = 0;
  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleMremap(uint32_t old_addr, uint32_t old_sz, uint32_t new_sz, uint32_t flags, uint32_t new_addr, uint32_t* return_value) {
  *return_value = 0xffffffffu;
  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleLlseek(int fd, uint32_t off_hi, uint32_t off_lo, uint32_t result, uint32_t whence, uint32_t* return_value) {
  uint64_t result_val = lseek64(
      fd,
      (static_cast<uint64_t>(off_hi) << 32) | static_cast<uint64_t>(off_lo),
      static_cast<int>(whence)
  );

  CHECK_TRAP(CopyToMemory(reinterpret_cast<void*>(&result_val), result, sizeof(uint64_t)));

  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleReadv(int fd, uint32_t vecs, uint32_t num_vecs, uint32_t* return_value) {
  IoVec vec;

  *return_value = 0;

  for (uint32_t i = 0; i != num_vecs; i++) {
    uint32_t bytes_written;

    CHECK_TRAP(CopyFromMemory(&vec, vecs + i * sizeof(IoVec), sizeof(IoVec)));
    CHECK_TRAP(HandleRead(fd, vec.base, vec.len, &bytes_written));

    *return_value += bytes_written;
  }

  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleWritev(int fd, uint32_t vecs, uint32_t num_vecs, uint32_t* return_value) {
  IoVec vec;

  *return_value = 0;

  for (uint32_t i = 0; i != num_vecs; i++) {
    uint32_t bytes_written;

    CHECK_TRAP(CopyFromMemory(&vec, vecs + i * sizeof(IoVec), sizeof(IoVec)));
    CHECK_TRAP(HandleWrite(fd, vec.base, vec.len, &bytes_written));

    *return_value += bytes_written;
  }

  return interp::Result::Ok;
}

enum class MmapFlags : uint32_t {
  Private = 0x02,
  Anonymous = 0x20
};

interp::Result SyscallHandler::HandleMmap(uint32_t address,
                                          uint32_t size,
                                          uint32_t prot,
                                          uint32_t flags,
                                          int fd,
                                          uint32_t off,
                                          uint32_t* return_value) {
  if (flags != (static_cast<uint32_t>(MmapFlags::Private) | static_cast<uint32_t>(MmapFlags::Anonymous))) {
    *return_value = static_cast<uint32_t>(-1);
    return interp::Result::Ok;
  } else if (address != 0 || (size & 0xfff) != 0) {
    *return_value = static_cast<uint32_t>(-1);
    return interp::Result::Ok;
  }

  auto* mem = env_->GetMemory(0);

  for (auto it = mmap_free_regions_.begin(); it != mmap_free_regions_.end(); ++it) {
    auto& r = *it;

    if (r.size == size) {
      *return_value = r.start;
      memset(reinterpret_cast<void*>(mem->data.data() + r.start), 0, size);

      mmap_free_regions_.erase(it);
      return interp::Result::Ok;
    } else if (r.size > size) {
      *return_value = r.start;
      memset(reinterpret_cast<void*>(mem->data.data() + r.start), 0, size);

      r.start += size;
      r.size -= size;
      return interp::Result::Ok;
    }
  }

  uint32_t max_pages = mem->page_limits.has_max ? mem->page_limits.max : WABT_MAX_PAGES;
  uint32_t cur_pages = mem->page_limits.initial;

  uint32_t new_pages = cur_pages + ((size + WABT_PAGE_SIZE - 1) & -WABT_PAGE_SIZE) / WABT_PAGE_SIZE;

  if (new_pages > max_pages) {
    *return_value = static_cast<uint32_t>(-1);
    return interp::Result::Ok;
  }

  mem->data.resize(new_pages * WABT_PAGE_SIZE);
  mem->page_limits.initial = new_pages;

  if (size != (new_pages - cur_pages) * WABT_PAGE_SIZE) {
    MmapFreeRegion r;

    r.start = cur_pages * WABT_PAGE_SIZE + size;
    r.size = (new_pages - cur_pages) * WABT_PAGE_SIZE - size;

    mmap_free_regions_.push_back(r);
  }

  *return_value = cur_pages * WABT_PAGE_SIZE;
  return interp::Result::Ok;
}

interp::Result SyscallHandler::HandleClockGetTime(uint32_t clock_id, uint32_t res, uint32_t* return_value) {
  timespec* res_p;

  CHECK_TRAP(GetMemoryAddress(res, sizeof(timespec), reinterpret_cast<void**>(&res_p)));
  *return_value = clock_gettime(clock_id, res_p);

  return interp::Result::Ok;
}

}
