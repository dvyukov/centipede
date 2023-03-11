#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common.h"
#include "help.h"
#include "syscalls.h"

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

#if BLENDER_LLVM_COVERAGE
extern "C" {
int __llvm_profile_runtime = 0;
void __llvm_profile_initialize_file();
void __llvm_profile_write_file();
}
#endif

namespace blender {
namespace {

constexpr int kProcessTimeoutSec = 5;
char input_data_buf[64 << 10];

void HandleStderrWrite(const char* data, uptr size) {
  // Cases where programs confusingly abort/check-fail on non-bugs.
  const char* not_bugs[] = {
      "Sanitizer: CHECK failed",
      "Sanitizer: out of memory",
      "Sanitizer: allocator is out of memory",
      "Sanitizer: requested allocation size",
      "Sanitizer failed to allocate",
      "uncaught exception of type std::bad_alloc",
      "LLVM ERROR: out of memory",
      ": Cannot allocate memory",  // perror output for ENOMEM
      // Glibc error message when we sent invalid netlink response.
      // TODO(dvyukov): ideally, we don't send invalid responses.
      "in __netlink_assert_response",
      "RAW: mmap error: 12",
      "RAW: Check mem != MAP_FAILED",
      "testing::internal::DeathTestAbort",
      "Check failed: !original_working_dir_.IsEmpty()",
      "exit() hanging: killing process with SIGABRT",
      "can't start helper thread",
  };
  for (const char* not_bug : not_bugs) {
    if (memmem(data, size, not_bug, strlen(not_bug))) {
      Syscall(SYS_write, kCommFD, data, size);
      EXIT("false bug pattern in output: '%s'", not_bug);
    }
  }
  // Grep for absl fatal error messages. They may or may not mean a bug,
  // the code is not consistent in their usage.
  constexpr char kAbslFatalLog[] = "F1111 11:11:11.111111 *****11 ";
  if (size > sizeof(kAbslFatalLog)) {
    char tmp[sizeof(kAbslFatalLog)] = {};
    for (uptr i = 0; i < sizeof(tmp) - 1; i++) {
      char c = data[i];
      if (kAbslFatalLog[i] == '*')
        c = kAbslFatalLog[i];
      else if (c >= '0' && c <= '9')
        c = '1';
      tmp[i] = c;
    }
    if (!strcmp(tmp, kAbslFatalLog)) {
      Syscall(SYS_write, kCommFD, data, size);
      EXIT("absl fatal log in output");
    }
  }
  // Additionally we need to look for the absl function that
  // terminates the process on fatal error messages.
  // Blender manages to turn off logging output with
  // --stderrthreshold=100000 and then we don't catch the message
  // before abort.
  const char* not_failed[] = {
      "LogMessageFatal::~LogMessageFatal",
  };
  for (const char* not_bug : not_failed) {
    if (memmem(data, size, not_bug, strlen(not_bug))) {
      Syscall(SYS_write, kCommFD, data, size);
      failed = false;
      EXIT("false bug pattern in output: '%s'", not_bug);
    }
  }
  const char* bugs[] = {
      "Sanitizer:",
      "Uninitialized bytes in",  // MSan output
      "runtime error: ",         // UBSan/CFI output
      "DEADLYSIGNAL",
      "panic: ",        // Go
      "fatal error: ",  // Go runtime
  };
  for (const char* bug : bugs) {
    if (memmem(data, size, bug, strlen(bug))) {
      LOG("bug pattern in output: '%s'", bug);
      allow_all = true;
      failed = true;
      break;
    }
  }
}

void Sigsys(int sig, siginfo_t* info, void* uctxp) {
  if (info->si_code != SYS_SECCOMP) return;
  ucontext_t* uctx = reinterpret_cast<ucontext_t*>(uctxp);
  auto& regs = reinterpret_cast<ucontext_t*>(uctxp)->uc_mcontext.gregs;
  const uptr pc = regs[REG_RIP];
  const int nr = regs[REG_RAX];
  uptr args[] = {
      static_cast<uptr>(regs[REG_RDI]), static_cast<uptr>(regs[REG_RSI]),
      static_cast<uptr>(regs[REG_RDX]), static_cast<uptr>(regs[REG_R10]),
      static_cast<uptr>(regs[REG_R8]),  static_cast<uptr>(regs[REG_R9]),
  };
  bool spoof = !allow_all;
  switch (nr) {
    case SYS_exit_group:
      EXIT("SYS_exit_group");

    case SYS_rt_sigaction:
      if ((args[0] == SIGSYS || args[0] == SIGALRM) && args[1]) {
        // Thou shall not pass!
        LOG("rt_sigaction(SIGSYS): nope");
        uctx->uc_mcontext.gregs[REG_RAX] = 0;
        return;
      }
      break;

    case SYS_write:
    case SYS_writev:
    case SYS_pwrite64:
    case SYS_sendmsg:
    case SYS_sendto:
      if (args[0] == STDOUT_FILENO || args[0] == STDERR_FILENO) {
        spoof = false;
        args[0] = kCommFD;
        if (nr == SYS_write)
          HandleStderrWrite(reinterpret_cast<char*>(args[1]), args[2]);
      }
      break;
  }

  bool real = false;
  std::optional<uptr> res;
  if (spoof) res = HandleSyscall(pc, nr, args);
  if (!res) {
    real = true;
    res = Syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
  }
  LOGV("%s(%d, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx",
       real ? "syscall" : "spoofed", nr, args[0], args[1], args[2], args[3],
       args[4], args[5], *res);
  regs[REG_RAX] = *res;
}

void Blend() {
#if BLENDER_LLVM_COVERAGE
  if (getenv("LLVM_PROFILE_FILE")) __llvm_profile_initialize_file();
#endif
  const char* seed = getenv("BLENDER_SEED");
  if (seed) {
    SetRandomSeed(atoi(seed));
  } else {
    ssize_t n = read(kCommFD, input_data_buf, sizeof(input_data_buf));
    if (n < 0) FAIL("read(kCommFD)");
    if (ftruncate(kCommFD, 0) < 0) FAIL("ftruncate(kCommFD)");
    SetRandomData(input_data_buf, n);
  }
  alarm(kProcessTimeoutSec);
  struct sigaction act = {};
  act.sa_sigaction = Sigsys;
  sigfillset(&act.sa_mask);
  sigdelset(&act.sa_mask, SIGSYS);
  act.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  if (sigaction(SIGSYS, &act, nullptr)) FAIL("sigaction");
  u32 syscall_pc_lo = reinterpret_cast<uptr>(&blender_syscall_addr);
  u32 syscall_pc_hi = reinterpret_cast<uptr>(&blender_syscall_addr) >> 32;
  const int permit[] = {
      SYS_rt_sigreturn, SYS_brk,         SYS_munmap,  SYS_mremap,
      SYS_mprotect,     SYS_madvise,     SYS_futex,   SYS_exit,
      SYS_sched_yield,  SYS_membarrier,  SYS_rseq,    SYS_set_robust_list,
      SYS_gettid,       SYS_getpid,      SYS_getgid,  SYS_getppid,
      SYS_getpgrp,      SYS_geteuid,     SYS_getegid, SYS_getuid,
      SYS_uname,        SYS_sigaltstack, SYS_sysinfo, SYS_clone,
      SYS_clone3,
  };
  const uptr npermit = sizeof(permit) / sizeof(permit[0]);
  sock_filter filter[8 + npermit] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 8),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, syscall_pc_lo, 0, 3),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, syscall_pc_hi, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
  };
  for (uptr i = 0; i < npermit; i++)
    filter[6 + i] = BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (u32)permit[i],
                             (u8)(npermit - i), 0);
  filter[6 + npermit] = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP);
  filter[7 + npermit] = BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
  struct sock_fprog prog {
    .len = u16(sizeof(filter) / sizeof(filter[0])), .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) FAIL("prctl(NO_NEW_PRIVS)");
  // TODO(dvyukov): consider using gVisor systrap syscall patching trick
  // to speed up interception. It needs to be done at the outer fork server
  // level to persist patches.
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
              reinterpret_cast<uptr>(&prog)))
    FAIL("seccomp(SECCOMP_SET_MODE_FILTER)");
}

__attribute__((noreturn)) void BlendedProcess(int comm_fd) {
  if (prctl(PR_SET_PDEATHSIG, SIGKILL)) FAIL("prctl(PDEATHSIG)");
  if (prctl(PR_SET_DUMPABLE, 0)) FAIL("prctl(DUMPABLE)");
  if (dup2(comm_fd, kCommFD) < 0) FAIL("dup2");
  if (syscall(SYS_close_range, kCommFD + 1, ~0u, 0)) FAIL("close_range");
  std::vector<std::string> argv = GenerateArgv();
  std::vector<char*> argp;
  for (auto& arg : argv) {
    LOG("arg: '%s'", arg.c_str());
    argp.push_back(arg.data());
  }
  argp.push_back(nullptr);
  std::vector<std::string> envv = GenerateEnv();
  envv.push_back("BLENDER_REEXECED=1");
  // LSan tries to use ptrace which we don't support, which leads to a deadlock.
  // If there is real ASAN_OPTIONS in the env, we will append it below.
  envv.push_back("ASAN_OPTIONS=detect_leaks=0");
  // More determinism.
  envv.push_back("GOMAXPROCS=1");
  const char* keep[] = {
      "BLENDER_LOG=",
      "BLENDER_SEED=",
      "LD_PRELOAD=",
      "ASAN_OPTIONS=",
      "MSAN_OPTIONS=",
      "TSAN_OPTIONS=",
      "CENTIPEDE_RUNNER_FLAGS=",
      "LLVM_PROFILE_FILE=",
  };
  for (char** e = environ; *e; e++) {
    for (const char* var : keep) {
      if (!strncmp(*e, var, strlen(var))) envv.push_back(*e);
    }
  }
  std::vector<char*> envp;
  for (auto& env : envv) {
    LOG("env: '%s'", env.c_str());
    envp.push_back(env.data());
  }
  envp.push_back(nullptr);
  // If we have any remaining randomness, pass it to the test process.
  auto [data, size] = GetRemainingRandomData();
  if (size) {
    if (write(kCommFD, data, size) != size) FAIL("write");
    if (lseek(kCommFD, 0, SEEK_SET) < 0) FAIL("lseek");
  }
  execve("/proc/self/exe", argp.data(), envp.data());
  FAIL("execve");
}

int TestInputImpl() {
  // Test one input.
  int comm_fd = memfd_create("blnder-comm", 0);
  if (comm_fd < 0) FAIL("memfd_create");
  int pid = fork();
  if (pid < 0) FAIL("fork");
  if (pid == 0) BlendedProcess(comm_fd);
  int status = 0;
  while (waitpid(-1, &status, __WALL) != pid) {
  }
  LOG("process exited with status %d/%d signal %d/%d\n", WIFEXITED(status),
      WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
  bool failed = ((WIFEXITED(status) && WEXITSTATUS(status)) ||
                 (WIFSIGNALED(status) && WTERMSIG(status) != SIGALRM));
  if (failed || getenv("BLENDER_OUTPUT")) {
    dprintf(STDERR_FILENO, "process exited with status %d/%d signal %d/%d\n",
            WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status),
            WTERMSIG(status));
    auto seed = GetOriginalRandomSeed();
    if (seed) dprintf(STDERR_FILENO, "BLENDER_SEED=%zu\n", *seed);
    if (lseek(comm_fd, 0, SEEK_SET) < 0) FAIL("lseek");
    char buf[4 << 10];
    for (;;) {
      int n = read(comm_fd, buf, sizeof(buf) - 1);
      if (n == 0) break;
      if (n < 0) FAIL("read");
      buf[n] = 0;
      if (write(STDERR_FILENO, buf, n) != n) FAIL("write");
    }
  }
  if (failed) _exit(1);
  close(comm_fd);
  return 0;
}

int TestInput(const char* data, size_t size) {
  SetRandomData(data, size);
  return TestInputImpl();
}

bool disabled;
char cmdline[4096];
const char* exe;
char* argv[64];
int argc;

// This runs before Centipede's fork server.
__attribute__((constructor(120))) void Preinit() {
  disabled = getenv("BLENDER_DISABLE");
  if (disabled) return;
  if (prctl(PR_SET_PDEATHSIG, SIGKILL)) FAIL("prctl(PDEATHSIG)");
  log_level = atoi(getenv("BLENDER_LOG") ?: "");
  LOG("preinit blender");
  int fd = open("/proc/self/cmdline", O_RDONLY);
  if (fd == -1) FAIL("open(/proc/self/cmdline)");
  auto n = read(fd, cmdline, sizeof(cmdline) - 1);
  if (n < 0) FAIL("read(/proc/self/cmdline)");
  close(fd);
  exe = strrchr(cmdline, '/');
  if (exe)
    exe++;
  else
    exe = cmdline;
  LOG("exe='%s'", exe);
  // These are usually used to "wrap" the target to debug/profile,
  // so assume these are not the target of fuzzing.
  if (!strcmp(exe, "gdb") || !strcmp(exe, "strace") || !strcmp(exe, "perf")) {
    disabled = true;
    return;
  }
  int argc = 0;
  for (char* pos = cmdline;
       pos < cmdline + n && argc < sizeof(argv) / sizeof(argv[0]) - 1;
       pos = pos + strlen(pos) + 1)
    argv[argc++] = pos;
  program_flags = ExtractHelpFlags();
}

// Needs to run after Centipede's global state constructor.
__attribute__((constructor(250))) void Init() {
  if (disabled) return;
  if (getenv("BLENDER_REEXECED")) {
    // This is forked test process.
    LOG("init blended");
    Blend();
    return;
  }
  LOG("init blender");
  // If this returns, we are not running under Centipede.
  MaybeCentipedeMain(argc, argv, TestInput);
  // Disable core dumps, they are slow.
  prctl(PR_SET_DUMPABLE, 0);
  if (argc > 1) {
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) FAIL("open('%s')", argv[1]);
    ssize_t n = read(fd, input_data_buf, sizeof(input_data_buf));
    if (n < 0) FAIL("read('%s')", argv[1]);
    close(fd);
    LOG("read %zu input bytes from input file", n);
    _exit(TestInput(input_data_buf, n));
  }
  const char* seed_env = getenv("BLENDER_SEED");
  if (seed_env) {
    SetRandomSeed(atoi(seed_env));
  } else {
    uptr seed = getpid();
    SetRandomSeed(seed);
    char seed_str[20];
    snprintf(seed_str, sizeof(seed_str), "%zu", seed);
    setenv("BLENDER_SEED", seed_str, true);
  }
  _exit(TestInputImpl());
}

}  // namespace

void LLVMDumpCoverage() {
#if BLENDER_LLVM_COVERAGE
  if (getenv("LLVM_PROFILE_FILE")) __llvm_profile_write_file();
#endif
}
}  // namespace blender
