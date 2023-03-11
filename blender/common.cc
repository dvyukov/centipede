#include "common.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdlib>

namespace blender {

int log_level;
int log_fd = STDERR_FILENO;
std::atomic<bool> failed;
std::atomic<bool> global_exiting;
__attribute__((tls_model("initial-exec"))) __thread bool exiting;
// TODO(dvyukov): when we enable it, theoretically rogue signal handlers
// can do bad things.
__attribute__((tls_model("initial-exec"))) __thread bool allow_all;

__attribute__((noinline)) uptr RawSyscall(uptr nr, uptr a0, uptr a1, uptr a2,
                                          uptr a3, uptr a4, uptr a5) {
  uptr res;
  asm volatile(
      "movq %5,%%r10; movq %6,%%r8; movq %7,%%r9;"
      "syscall;"
      ".globl blender_syscall_addr;"
      "blender_syscall_addr: nop;"
      : "=a"(res)
      : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(a3), "r"(a4), "r"(a5)
      : "r8", "r9", "r10", "r11", "rcx", "memory");
  return res;
}

void Logf(const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  char buf[256];
  vsnprintf(buf, sizeof(buf) - 1, msg, args);
  buf[sizeof(buf) - 1] = 0;
  va_end(args);
  Syscall(SYS_write, log_fd, reinterpret_cast<uptr>(buf), strlen(buf));
}

void ExitDontCall(const char* msg, ...) {
  if (failed || log_level) {
    va_list args;
    va_start(args, msg);
    char buf[256];
    vsnprintf(buf, sizeof(buf) - 1, msg, args);
    buf[sizeof(buf) - 1] = 0;
    va_end(args);
    Syscall(SYS_write, STDERR_FILENO, reinterpret_cast<uptr>(buf), strlen(buf));
  }
  if (!exiting) {
    exiting = true;
    // If another thread is exiting (writing coverage), just wait for it.
    if (global_exiting.exchange(true))
      for (;;) sleep(1000);
    alarm(60);  // update the timeout alarm
    if (!failed) {
      CentipedeDumpCoverage();
      LLVMDumpCoverage();
    }
  }
  Syscall(SYS_exit_group, failed ? EXIT_FAILURE : EXIT_SUCCESS);
  __builtin_unreachable();
}

__attribute__((weak)) void MaybeCentipedeMain(int argc, char** argv,
                                              int (*test_cb)(const char* data,
                                                             size_t size)) {}
__attribute__((weak)) void CentipedeDumpCoverage() {}

__attribute__((weak)) void LLVMDumpCoverage() {}

}  // namespace blender
