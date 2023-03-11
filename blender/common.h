#ifndef BLENDER_COMMON_H_
#define BLENDER_COMMON_H_

#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>

#ifndef SYS_rseq
#define SYS_rseq 334
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

namespace blender {

typedef unsigned long uptr;
typedef long sptr;
typedef unsigned u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define STRINGIFY1(S) #S
#define STRINGIFY(S) STRINGIFY1(S)

constexpr int kCommFD = STDERR_FILENO + 1;

extern int log_level;
extern int log_fd;
extern std::atomic<bool> failed;
__attribute__((tls_model("initial-exec"))) extern __thread bool allow_all;

#define LOG(msg, ...) LOGL(1, msg, ##__VA_ARGS__)
#define LOGV(msg, ...) LOGL(2, msg, ##__VA_ARGS__)
#define LOGL(level, msg, ...)                                   \
  do {                                                          \
    if (__builtin_expect(log_level >= (level), false))          \
      Logf(__FILE_NAME__ ":" STRINGIFY(__LINE__) ": " msg "\n", \
           ##__VA_ARGS__);                                      \
  } while (false)

// We don't need allow_all call per se, but there is a bug in ASan:
// it injects __asan_handle_no_return() call before calls to noreturn
// functions and it may crash in sigaltstack interceptor when
// REAL(sigaltstack) == nullptr.
#define FAIL(msg, ...)                                                   \
  do {                                                                   \
    allow_all = true;                                                    \
    failed = true;                                                       \
    ExitDontCall(__FILE_NAME__ ":" STRINGIFY(__LINE__) ": FAIL: " msg    \
                                                       " (errno: %s)\n", \
                 ##__VA_ARGS__, strerror(errno));                        \
  } while (false)

// The the comment on FAIL for allow_all.
#define EXIT(msg, ...)                                                      \
  do {                                                                      \
    allow_all = true;                                                       \
    ExitDontCall(__FILE_NAME__ ":" STRINGIFY(__LINE__) ": EXIT: " msg "\n", \
                 ##__VA_ARGS__);                                            \
  } while (false)

__attribute__((format(printf, 1, 2))) void Logf(const char* msg, ...);
__attribute__((noreturn, format(printf, 1, 2))) void ExitDontCall(
    const char* msg, ...);

uptr RawSyscall(uptr nr, uptr a0, uptr a1, uptr a2, uptr a3, uptr a4, uptr a5);

template <class A0 = uptr, class A1 = uptr, class A2 = uptr, class A3 = uptr,
          class A4 = uptr, class A5 = uptr>
uptr Syscall(uptr nr, A0 a0 = 0, A1 a1 = 0, A2 a2 = 0, A3 a3 = 0, A4 a4 = 0,
             A5 a5 = 0) {
  return RawSyscall(nr, (uptr)a0, (uptr)a1, (uptr)a2, (uptr)a3, (uptr)a4,
                    (uptr)a5);
}

extern "C" void* blender_syscall_addr;

void MaybeCentipedeMain(int argc, char** argv,
                        int (*test_cb)(const char* data, size_t size));
void CentipedeDumpCoverage();
void LLVMDumpCoverage();

}  // namespace blender

#endif  // BLENDER_COMMON_H_
