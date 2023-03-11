#include "syscalls.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>

#include "help.h"

#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 3
#endif

namespace blender {
namespace {

constexpr uptr kFakeFDStart = 42000;
std::atomic<int> fd_seq{kFakeFDStart};

// If input_data_random is set, then we are using pseudo-random input
// data generation with the seed in input_data_seed.
// Otherwise, the input data is in input_data_pos/input_data_end.
bool input_data_random;
unsigned input_data_seed;
unsigned input_data_state;
const char* input_data_pos;
const char* input_data_end;

bool OneOf(uptr n) {
  char v;
  if (input_data_pos + sizeof(v) <= input_data_end)
    v = *input_data_pos++;
  else
    v = rand_r(&input_data_state);
  return (v % n) == 0;
}

uptr RandInt(uptr n = -1) {
  if (n <= 1) return 0;
  uptr v;
  if (input_data_pos + sizeof(v) <= input_data_pos) {
    v = *reinterpret_cast<const uptr*>(input_data_pos);
    input_data_pos += sizeof(v);
  } else {
    v = rand_r(&input_data_state);
  }
  if (v == -1) return v;
  return v % n;
}

void RandData(void* addr, uptr n) {
  for (uptr i = 0; i < n; i++) {
    char v;
    if (input_data_pos + sizeof(v) <= input_data_end)
      v = *input_data_pos++;
    else
      v = rand_r(&input_data_state);
    static_cast<char*>(addr)[i] = v;
  }
}

std::string RandString(uptr max_size) {
  std::string val(RandInt(max_size), 0);
  RandData(val.data(), val.size());
  return val;
}

std::string RandArg() {
  // TODO(dvyukov): need something more generic, this is just for curl/ares.
  switch (RandInt(20)) {
    default:
      return RandString(10);
    case 0:
      return "localhost";
    case 1:
      return "blender.localhost";
    case 2:
      return "127.0.0.1";
    case 3:
      return "::1";
    case 4:
      return "http://localhost/foo";
    case 5:
      return "ftp://localhost/foo";
  }
}

bool IsRealFD(uptr fd) { return fd > kCommFD && fd < kFakeFDStart; }

struct SockAddr {
  socklen_t size;
  char data[128];
};

// TODO(dvyukov): need better containers and serialization.
SockAddr sock_addrs[16];
uptr sock_addr_count;

void NoteSockAddr(const sockaddr* addr, socklen_t addrlen) {
  if (!addr || !addrlen ||
      sock_addr_count >= sizeof(sock_addrs) / sizeof(sock_addrs[0]))
    return;
  auto& slot = sock_addrs[sock_addr_count++];
  slot.size = std::min<socklen_t>(addrlen, sizeof(slot.data));
  memcpy(slot.data, addr, slot.size);
}

void GenerateSockAddr(sockaddr* ptr, socklen_t* addrlen) {
  if (!ptr || !addrlen || !*addrlen) return;
  if (!sock_addr_count || OneOf(10)) {
    *addrlen = RandInt(*addrlen);
    RandData(ptr, *addrlen);
  } else {
    auto& addr = sock_addrs[RandInt(sock_addr_count)];
    *addrlen = std::min(*addrlen, addr.size);
    memcpy(ptr, addr.data, *addrlen);
  }
}

template <class R>
Result ConvRes(std::optional<R> res) {
  if (!res) return {};
  return uptr(*res);
}

template <class R>
Result ConvRes(R res) {
  return uptr(res);
}

template <class R>
Result Handle(R (*f)(), uptr* a) {
  return ConvRes(f());
}

template <class R, class A0>
Result Handle(R (*f)(A0), uptr* a) {
  return ConvRes(f(A0(a[0])));
}

template <class R, class A0, class A1>
Result Handle(R (*f)(A0, A1), uptr* a) {
  return ConvRes(f(A0(a[0]), A1(a[1])));
}

template <class R, class A0, class A1, class A2>
Result Handle(R (*f)(A0, A1, A2), uptr* a) {
  return ConvRes(f(A0(a[0]), A1(a[1]), A2(a[2])));
}

template <class R, class A0, class A1, class A2, class A3>
Result Handle(R (*f)(A0, A1, A2, A3), uptr* a) {
  return ConvRes(f(A0(a[0]), A1(a[1]), A2(a[2]), A3(a[3])));
}

template <class R, class A0, class A1, class A2, class A3, class A4>
Result Handle(R (*f)(A0, A1, A2, A3, A4), uptr* a) {
  return ConvRes(f(A0(a[0]), A1(a[1]), A2(a[2]), A3(a[3]), A4(a[4])));
}

template <class R, class A0, class A1, class A2, class A3, class A4, class A5>
Result Handle(R (*f)(A0, A1, A2, A3, A4, A5), uptr* a) {
  return ConvRes(f(A0(a[0]), A1(a[1]), A2(a[2]), A3(a[3]), A4(a[4]), A5(a[5])));
}

std::optional<int> sys_sigaltstack(const stack_t* ss, stack_t* old_ss) {
  if (ss) return 0;
  return {};
}

std::optional<int> sys_rt_sigaction(int sig, struct sigaction* act,
                                    struct sigaction* oact, size_t sigsetsize) {
  // TODO(dvyukov): strictly speaking act is const.
  if (act) sigdelset(&act->sa_mask, SIGSYS);
  return {};
}

std::optional<int> sys_rt_sigprocmask(int how, sigset_t* nset, sigset_t* oset,
                                      size_t sigsetsize) {
  if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)
    return -EINVAL;
  return 0;
}

std::optional<uptr> sys_kill(pid_t pid, int sig) {
  if (pid == Syscall(SYS_getpid)) return {};
  return 0;
}

std::optional<uptr> sys_tgkill(pid_t tgid, pid_t tid, int sig) {
  if (sig == SIGABRT && tgid == Syscall(SYS_getpid)) {
    LOG("detected abort");
    failed = true;
  }
  return {};
}

std::optional<void*> sys_mmap(void* addr, uptr len, uptr prot, uptr flags,
                              int fd, uptr pgoff) {
  if ((flags & MAP_ANON) || IsRealFD(fd)) return {};
  flags &= ~(MAP_SHARED | MAP_SHARED_VALIDATE);
  flags |= MAP_PRIVATE | MAP_ANON;
  prot |= PROT_WRITE;
  addr =
      reinterpret_cast<void*>(Syscall(SYS_mmap, addr, len, prot, flags, -1, 0));
  if (addr != MAP_FAILED) RandData(addr, std::min<uptr>(len, 4 << 10));
  return addr;
}

int sys_connect(int fd, const sockaddr* addr, socklen_t addrlen) {
  NoteSockAddr(addr, addrlen);
  return 0;
}

ssize_t sys_sendto(int fd, const void* buf, size_t len, int flags,
                   const sockaddr* addr, socklen_t addrlen) {
  NoteSockAddr(addr, addrlen);
  return RandInt(len + 1);
}

int sys_getsockopt(int fd, int level, int optname, void* val,
                   socklen_t* optlen) {
  // TODO: implement other options.
  if (level == SOL_SOCKET && optname == SO_ERROR)
    *static_cast<u32*>(val) = OneOf(10) ? 0 : ENOTCONN;
  return 0;
}

int sys_getsockname(int fd, sockaddr* addr, socklen_t* addrlen) {
  GenerateSockAddr(addr, addrlen);
  return 0;
}

int sys_getpeername(int fd, sockaddr* addr, socklen_t* addrlen) {
  GenerateSockAddr(addr, addrlen);
  return 0;
}

int sys_ppoll(pollfd* ufds, unsigned nfds, timespec* tsp,
              const sigset_t* sigmask, size_t sigsetsize) {
  int ready = 0;
  for (unsigned i = 0; i < nfds; i++) {
    auto& ev = ufds[i];
    ev.revents = 0;
    if ((ev.events & POLLIN) && OneOf(2)) ev.revents |= POLLIN;
    if ((ev.events & POLLOUT) && OneOf(2)) ev.revents |= POLLOUT;
    if ((ev.events & POLLRDBAND) && OneOf(3)) ev.revents |= POLLRDBAND;
    if ((ev.events & POLLWRBAND) && OneOf(3)) ev.revents |= POLLWRBAND;
    if ((ev.events & POLLPRI) && OneOf(10)) ev.revents |= POLLPRI;
    if ((ev.events & POLLRDHUP) && OneOf(10)) ev.revents |= POLLRDHUP;
    if (OneOf(20)) ev.revents |= POLLHUP;
    if (OneOf(20)) ev.revents |= POLLERR;
    if (ev.revents) ready++;
  }
  return ready;
}

int sys_poll(pollfd* ufds, unsigned nfds, int timeout_msecs) {
  return sys_ppoll(ufds, nfds, nullptr, nullptr, 0);
}

int sys_pipe2(int fds[2], int flags) {
  fds[0] = fd_seq++;
  fds[1] = fd_seq++;
  return 0;
}

int sys_pipe(int fds[2]) { return sys_pipe2(fds, 0); }

int sys_statfs(const char* filename, struct statfs* buf) {
  RandData(buf, sizeof(*buf));
  return 0;
}

int sys_fstatfs(int fd, struct statfs* buf) {
  RandData(buf, sizeof(*buf));
  return 0;
}

uptr sys_getcwd(char* buf, uptr size) {
  if (size < 2) return -ERANGE;
  uptr n = RandInt(size);
  RandData(buf, n);
  buf[0] = '/';
  buf[n] = 0;
  return n + 1;
}

uptr sys_readlinkat(int dfd, const char* pathname, char* buf, int bufsiz) {
  uptr n = RandInt(bufsiz);
  RandData(buf, n);
  return n;
}

uptr sys_readlink(const char* pathname, char* buf, int bufsiz) {
  return sys_readlinkat(AT_FDCWD, pathname, buf, bufsiz);
}

std::optional<ssize_t> sys_pread64(int fd, char* buf, size_t count,
                                   loff_t pos) {
  if (IsRealFD(fd)) return {};
  if (count && OneOf(2)) count = RandInt(count);
  RandData(buf, count);
  return count;
}

std::optional<ssize_t> sys_read(int fd, char* buf, size_t count) {
  return sys_pread64(fd, buf, count, -1);
}

ssize_t sys_recvfrom(int fd, char* buf, size_t size, unsigned flags,
                     sockaddr* addr, socklen_t* addrlen) {
  GenerateSockAddr(addr, addrlen);
  uptr n = RandInt(size);
  RandData(buf, n);
  return n;
}

ssize_t sys_recvmsg(int fd, msghdr* msg, int flags) {
  if (msg->msg_namelen) {
    msg->msg_namelen = RandInt(msg->msg_namelen) + 1;
    RandData(msg->msg_name, msg->msg_namelen);
  }
  uptr n = 0;
  if (msg->msg_iovlen) {
    n = RandInt(msg->msg_iov[0].iov_len) + 1;
    RandData(msg->msg_iov[0].iov_base, n);
  }
  // TODO(dvyukov): fill control data,
  msg->msg_controllen = 0;
  msg->msg_flags = RandInt(-1);
  return n;
}

std::optional<ssize_t> sys_pwrite64(int fd, const char* buf, size_t count,
                                    size_t pos) {
  if (IsRealFD(fd)) return {};
  uptr n = RandInt(count + 1);
  // Note: Go runtime will throw if a pipe write fails with anything other
  // than EINTR/EAGAIN.
  if (!n || OneOf(20)) return -EINTR;
  return n;
}

std::optional<ssize_t> sys_write(int fd, const char* buf, size_t count) {
  return sys_pwrite64(fd, buf, count, -1);
}

std::optional<ssize_t> sys_writev(int fd, const iovec* vec, uptr vlen) {
  if (IsRealFD(fd)) return {};
  if (OneOf(10)) return -EINTR;
  // TODO(dvyukov): count how many bytes there is.
  return 1;
}

std::optional<ssize_t> sys_sendmsg(int fd, msghdr* msg, int flags) {
  if (IsRealFD(fd)) return {};
  if (OneOf(10)) return -EINTR;
  // TODO(dvyukov): count how many bytes there is.
  return 1;
}

int sys_epoll_create(int size) { return fd_seq++; }

int sys_epoll_create1(int flags) { return fd_seq++; }

int sys_epoll_ctl(int epfd, int op, int fd, epoll_event* ev) { return 0; }

int sys_epoll_pwait2(int epfd, epoll_event* events, int maxevents,
                     timespec* timeout, const sigset_t* sigmask,
                     size_t sigsetsize) {
  // TODO(dvyukov): sleep for a bit if timeout is provided to avoid busy
  // looping (here and in all other blocking syscalls).
  return 0;
}

int sys_epoll_pwait(int epfd, epoll_event* events, int maxevents, int timeout,
                    const sigset_t* sigmask, size_t sigsetsize) {
  return sys_epoll_pwait2(epfd, events, maxevents, nullptr, sigmask,
                          sigsetsize);
}

int sys_epoll_wait(int epfd, epoll_event* events, int maxevents, int timeout) {
  return sys_epoll_pwait(epfd, events, maxevents, timeout, nullptr, 0);
}

int sys_inotify_init1(int flags) { return fd_seq++; }

int sys_inotify_init() { return sys_inotify_init1(0); }

int sys_inotify_add_watch(int fd, const char* pathname, u32 mask) { return 1; }

int sys_inotify_rm_watch(int fd, int wd) { return 0; }

int sys_wait4(pid_t pid, int* stat_addr, int options, struct rusage* ru) {
  if (OneOf(100)) return -EINTR;
  if (stat_addr) *stat_addr = RandInt();
  if (ru) RandData(ru, sizeof(*ru));
  // TODO(dvyukov): keep track of subprocesses.
  // A program may pass pid=-1 but still expect to wait for particular
  // subprocesses.
  if (pid <= 0) return 123;
  return pid;
}

int sys_waitid(int which, pid_t pid, siginfo_t* infop, int options,
               struct rusage* ru) {
  if (OneOf(100)) return -EINTR;
  if (ru) RandData(ru, sizeof(*ru));
  infop->si_uid = 0;
  infop->si_signo = SIGCHLD;
  infop->si_status = RandInt();
  infop->si_code = RandInt(CLD_CONTINUED) + 1;
  if (which == P_PID)
    infop->si_pid = pid;
  else
    infop->si_pid = 123;
  return 0;
}

// TODO(dvyukov): these are arch-specific.
struct old_kernel_stat {
  u16 dev;
  u16 ino;
  u16 mode;
  u16 nlink;
  u16 uid;
  u16 gid;
  u16 rdev;
  u32 size;
  u32 atime;
  u32 mtime;
  u32 ctime;
};

struct kernel_stat {
  uptr dev;
  uptr ino;
  uptr nlink;
  u32 mode;
  u32 uid;
  u32 gid;
  u32 pad0;
  uptr rdev;
  uptr size;
  uptr blksize;
  uptr blocks;
  uptr atime;
  uptr atime_nsec;
  uptr mtime;
  uptr mtime_nsec;
  uptr ctime;
  uptr ctime_nsec;
  uptr unused[3];
};

int sys_stat(const char* filename, old_kernel_stat* stat) {
  RandData(stat, sizeof(*stat));
  return 0;
}

int sys_lstat(const char* filename, old_kernel_stat* stat) {
  return sys_stat(filename, stat);
}

std::optional<int> sys_fstat(int fd, old_kernel_stat* stat) {
  if (IsRealFD(fd)) return {};
  RandData(stat, sizeof(*stat));
  return 0;
}

int sys_newfstatat(int dfd, const char* filename, kernel_stat* stat, int flag) {
  RandData(stat, sizeof(struct stat));
  stat->mode &= 0xffff;
  stat->atime_nsec %= 1000000000;
  stat->mtime_nsec %= 1000000000;
  stat->ctime_nsec %= 1000000000;
  // TODO(dvyukov): Libc++ has an int overflow for very large time values.
  stat->atime %= 1000000000;
  stat->mtime %= 1000000000;
  stat->ctime %= 1000000000;
  return 0;
}

int sys_dup(int fd) { return fd_seq++; }

int sys_dup3(int fd, int newfd, int flags) { return newfd; }

int sys_dup2(int fd, int newfd) { return sys_dup3(fd, newfd, 0); }

int sys_mknodat(int dfd, const char* filename, int mode, unsigned int dev) {
  return fd_seq++;
}

int sys_socket(int family, int type, int proto) { return fd_seq++; }

int sys_socketpair(int family, int type, int proto, int fds[2]) {
  fds[0] = fd_seq++;
  fds[1] = fd_seq++;
  return 0;
}

int sys_accept4(int fd, sockaddr* addr, socklen_t* addrlen, int flags) {
  GenerateSockAddr(addr, addrlen);
  return fd_seq++;
}

int sys_accept(int fd, sockaddr* addr, socklen_t* addrlen) {
  return sys_accept4(fd, addr, addrlen, 0);
}

std::optional<int> sys_openat(int dfd, const char* filename, int flags,
                              int mode) {
  LOGV("open(%s, %d, 0x%x)", filename, flags, mode);
  // Allow read-only access to some file.
  // Libc parses some of these e.g. to obtain number of CPUs from
  // /sys/devices/system/cpu/online, /proc/stat, /proc/cpuinfo.
  // If we return random contents, it returns 0 CPUs and some code
  // aborts on that. We can spoof contents of these files as well,
  // but we need to return something realistic as contents.
  // For now we just proxy to the actual files.
  if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT) &&
      (!strncmp(filename, "/sys/", sizeof("/sys/") - 1) ||
       !strncmp(filename, "/proc/", sizeof("/proc/") - 1) ||
       !strncmp(filename, "/etc/", sizeof("/etc/") - 1)))
    return {};
  // LLVM has a bug in parsing of these files.
  // if (strstr(fname, "cuda")) return -EIO;
  return fd_seq++;
}

std::optional<int> sys_open(const char* filename, int flags, int mode) {
  return sys_openat(AT_FDCWD, filename, flags, mode);
}

std::optional<int> sys_close(int fd) {
  if (IsRealFD(fd)) return {};
  return 0;
}

std::optional<int> sys_lseek(int fd, off_t offset, int whence) {
  if (IsRealFD(fd)) return {};
  return 0;
}

std::optional<int> sys_fcntl(int fd, int cmd, uptr arg) {
  if (IsRealFD(fd)) return {};
  return 0;
}

std::optional<int> sys_ftruncate(int fd, uptr length) {
  if (IsRealFD(fd)) return {};
  return 0;
}

int sys_restart_syscall() {
  // TODO(dvyukov): The return value of restart_syscall() is the return
  // value of whatever system call is being restarted.
  // But we don't know what system call is being restarted
  // (nor if it was a real syscall or our faked syscall).
  return 0;
}
}  // namespace

#define INTERCEPT(N) \
  case SYS_##N:      \
    return Handle(sys_##N, args);
#define SYSCALL(N) \
  case SYS_##N:    \
    return {};
#define IGNORE(N) \
  case SYS_##N:   \
    return 0;
#define ERROR(N) \
  case SYS_##N:  \
    return -ENOMEM;

Result HandleSyscall(const uptr pc, const uptr nr, uptr args[kSyscallArgs]) {
  if (OneOf(10000)) return -ENOMEM;

  switch (nr) {
    INTERCEPT(rt_sigaction);
    INTERCEPT(sigaltstack);
    INTERCEPT(rt_sigprocmask);
    INTERCEPT(mmap);
    INTERCEPT(connect);
    INTERCEPT(sendto);
    INTERCEPT(getsockopt);
    INTERCEPT(getsockname);
    INTERCEPT(getpeername);
    INTERCEPT(poll);
    INTERCEPT(ppoll);
    INTERCEPT(pipe);
    INTERCEPT(pipe2);
    INTERCEPT(kill);
    INTERCEPT(tgkill);
    INTERCEPT(statfs);
    INTERCEPT(fstatfs);
    INTERCEPT(getcwd);
    INTERCEPT(readlinkat);
    INTERCEPT(readlink);
    INTERCEPT(read);
    INTERCEPT(pread64);
    INTERCEPT(recvfrom)
    INTERCEPT(recvmsg);
    INTERCEPT(write);
    INTERCEPT(writev);
    INTERCEPT(sendmsg);
    INTERCEPT(pwrite64);
    INTERCEPT(epoll_create);
    INTERCEPT(epoll_create1);
    INTERCEPT(epoll_ctl);
    INTERCEPT(epoll_wait);
    INTERCEPT(epoll_pwait);
    INTERCEPT(epoll_pwait2);
    INTERCEPT(inotify_init);
    INTERCEPT(inotify_init1);
    INTERCEPT(inotify_add_watch);
    INTERCEPT(inotify_rm_watch);
    INTERCEPT(wait4);
    INTERCEPT(waitid);
    INTERCEPT(stat);
    INTERCEPT(fstat);
    INTERCEPT(lstat);
    INTERCEPT(newfstatat);
    INTERCEPT(dup);
    INTERCEPT(dup2);
    INTERCEPT(dup3);
    INTERCEPT(mknodat);
    INTERCEPT(socket);
    INTERCEPT(socketpair);
    INTERCEPT(accept);
    INTERCEPT(accept4);
    INTERCEPT(open);
    INTERCEPT(openat);
    INTERCEPT(close);
    INTERCEPT(lseek);
    INTERCEPT(fcntl);
    INTERCEPT(ftruncate);
    INTERCEPT(restart_syscall);

    // TODO(dvyukov): implement me.
    ERROR(fork);
    ERROR(execve);
    ERROR(ptrace);
    ERROR(shmget);
    SYSCALL(getrusage);
    SYSCALL(getrlimit);
    SYSCALL(getdents);
    SYSCALL(getdents64);
    SYSCALL(getrandom);
    SYSCALL(prlimit64);
    SYSCALL(getcpu);
    SYSCALL(mincore);
    SYSCALL(sched_getaffinity);
    SYSCALL(clock_gettime);
    SYSCALL(getpriority);
    SYSCALL(get_mempolicy);

    // TODO(dvyukov): implement some of these, move the rest to the seccomp
    // filter.
    IGNORE(prctl);
    IGNORE(seccomp);
    IGNORE(alarm);
    IGNORE(setitimer);
    IGNORE(getitimer);
    IGNORE(setpriority);
    IGNORE(set_mempolicy);
    IGNORE(clock_nanosleep);
    IGNORE(nanosleep);
    IGNORE(umask);
    IGNORE(setuid);
    IGNORE(setgid);
    IGNORE(setsid);
    IGNORE(setpgid);
    IGNORE(setreuid);
    IGNORE(setregid);
    IGNORE(setresuid);
    IGNORE(setresgid);
    IGNORE(listen);
    IGNORE(bind);
    IGNORE(setsockopt);
    IGNORE(chdir);
    IGNORE(fchdir);
    IGNORE(ioctl);
    IGNORE(access);
    IGNORE(rename);
    IGNORE(unlink);
    IGNORE(symlink);
    IGNORE(mkdir);
    IGNORE(mkdirat);

    default:
      FAIL(
          "unknown syscall(%zu, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) "
          "at 0x%lx",
          nr, args[0], args[1], args[2], args[3], args[4], args[5], pc);
  }
}

std::vector<std::string> GenerateArgv() {
  std::vector<std::string> argv{OneOf(10) ? RandString(10) : "/blended"};
  // TODO(dvyukov): LLVM has a bug around this (expects non-empty argv[0]).
  while (argv[0].empty()) argv[0] = RandString(10);
  while (!OneOf(3)) {
    Flag new_flag;
    const Flag* flag = &new_flag;
    if (program_flags.empty() || OneOf(100))
      new_flag = {RandString(10), kFlagUnknown};
    else
      flag = &program_flags[RandInt(program_flags.size())];
    auto type = flag->type;
    if (type == kFlagUnknown && OneOf(2))
      type = static_cast<FlagType>(RandInt(kFlagTypeLast) + 1);
    switch (type) {
      case kFlagUnknown:
        if (OneOf(10)) {
          argv.push_back(flag->name + RandArg());
        } else {
          argv.push_back(flag->name);
          argv.push_back(RandArg());
        }
        break;
      case kFlagBinary:
        argv.push_back(flag->name);
        break;
      case kFlagString:
        argv.push_back(flag->name + "=" + RandArg());
        break;
      case kFlagDouble:
        argv.push_back(flag->name + "=" +
                       std::to_string(static_cast<double>(RandInt() / 10)));
        break;
      case kFlagBool:
        argv.push_back(flag->name + (OneOf(2) ? "=true" : "=false"));
        break;
      case kFlagInt:
        argv.push_back(flag->name + "=" +
                       std::to_string(static_cast<int64_t>(RandInt())));
        break;
    }
  }
  // Non-flag arguments.
  while (OneOf(2)) argv.push_back(RandArg());
  return argv;
}

std::vector<std::string> GenerateEnv() {
  std::vector<std::string> envv;
  // TODO(dvyukov): extract env automatically (intercept getenv).
  while (!OneOf(3)) envv.push_back(RandString(10));
  return envv;
}

void SetRandomSeed(uptr seed) {
  LOG("got random seed %zu", seed);
  input_data_random = true;
  input_data_seed = seed;
  input_data_state = seed;
}

void SetRandomData(const char* data, uptr size) {
  if (input_data_random) FAIL("input_data_random is set");
  if (unsetenv("BLENDER_SEED")) FAIL("unsetenv('BLENDER_SEED')");
  LOG("got %zu input bytes", size);
  input_data_pos = data;
  input_data_end = data + size;
}

std::optional<uptr> GetOriginalRandomSeed() {
  if (!input_data_random) return {};
  return input_data_seed;
}

std::pair<const void*, uptr> GetRemainingRandomData() {
  return {input_data_pos, input_data_end - input_data_pos};
}

}  // namespace blender
