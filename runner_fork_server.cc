// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Fork server, a.k.a. a process Zygote, for the Centipede runner.
//
// Startup:
// * Centipede creates two named FIFO pipes: pipe0 and pipe1.
// * Centipede runs the target in background, and passes the FIFO names to it
//   using two environment variables: CENTIPEDE_FORK_SERVER_FIFO[01].
// * Centipede opens the pipe0 for writing, pipe1 for reading.
//   These would block until the same pipes are open in the runner.
// * Runner, early at startup, checks if it is given the pipe names.
//    If so, it opens pipe0 for reading, pipe1 for writing,
//    and enters the infinite fork-server loop.
// Loop:
// * Centipede writes a byte to pipe0.
// * Runner blocks until it reads a byte from pipe0, then forks and waits.
//   This is where the child process executes and does the work.
//   This works because every execution of the target has the same arguments.
// * Runner receives the child exit status and writes it to pipe1.
// * Centipede blocks until it reads the status from pipe1.
// Exit:
// * Centipede closes the pipes (and then deletes them).
// * Runner (the fork server) fails on the next read from pipe0 and exits.
//
// The fork server code kicks in super-early in the process startup,
// via injecting itself into the .preinit_array.
// Ensure that this code is not dropped from linking (alwayslink=1).
//
// The main benefts of the fork server over plain fork/exec or system() are:
//  * Dynamic linking happens once at the fork-server startup.
//  * fork is cheaper than fork/exec, especially when running multiple threads.
//
// Other than performance, using fork server should be the same as not using it.
//
// Similar ideas:
// * lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
// * Android Zygote.

#include <fcntl.h>
#include <linux/limits.h>  // ARG_MAX
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

namespace centipede {

// Writes a C string to stderr when debugging, no-op otherwise.
void Log(const char *str) {
  // Uncomment these lines to debug.
  // (void)write(STDERR_FILENO, str, strlen(str));
  // fsync(STDERR_FILENO);
}

// Maybe writes the `reason` to stderr; then calls _exit.
void Exit(const char *reason) {
  Log(reason);
  _exit(0);  // The exit code does not matter, it won't be checked anyway.
}

// Starts the fork server if the pipes are given.
// This function is called from .preinit_array when linked statically,
// or from the DSO constructor when injected via LD_PRELOAD.
// Note: it must run before the GlobalRunnerState constructor because
// GlobalRunnerState may terminate the process early due to an error,
// then we never open the fifos and the corresponding opens in centipede
// hang forever.
// The priority 150 is chosen on the lower end (higher priority)
// of the user-available range (101-999) to allow ordering with other
// constructors and C++ constructors (init_priority). Note: constructors
// without explicitly specified priority run after all constructors with
// explicitly specified priority, thus we still run before most
// "normal" constructors.
__attribute__((constructor(150))) void ForkServerCallMeVeryEarly() {
  const char *pipe0_name = getenv("CENTIPEDE_FORK_SERVER_FIFO0");
  const char *pipe1_name = getenv("CENTIPEDE_FORK_SERVER_FIFO1");
  if (!pipe0_name || !pipe1_name) return;
  Log("###Centipede fork server requested\n");
  int pipe0 = open(pipe0_name, O_RDONLY);
  if (pipe0 < 0) Exit("###open pipe0 failed\n");
  int pipe1 = open(pipe1_name, O_WRONLY);
  if (pipe1 < 0) Exit("###open pipe1 failed\n");
  Log("###Centipede fork server ready\n");

  // Loop.
  while (true) {
    Log("###Centipede fork server blocking on pipe0\n");
    // This read will fail when Centipede shuts down the pipes.
    char ch = 0;
    if (read(pipe0, &ch, 1) != 1) Exit("###read from pipe0 failed\n");
    Log("###Centipede starting fork\n");
    auto pid = fork();
    if (pid < 0) {
      Exit("###fork failed\n");
    } else if (pid == 0) {
      // Child process. Reset stdout/stderr and let it run normally.
      for (int fd = 1; fd <= 2; fd++) {
        lseek(fd, 0, SEEK_SET);
        // NOTE: Allow ftruncate() to fail by ignoring its return; that okay to
        // happen when the stdout/stderr are not redirected to a file.
        (void)ftruncate(fd, 0);
      }
      return;
    } else {
      // Parent process.
      int status = -1;
      if (waitpid(pid, &status, 0) < 0) Exit("###waitpid failed\n");
      if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == EXIT_SUCCESS)
          Log("###Centipede fork returned EXIT_SUCCESS\n");
        else if (WEXITSTATUS(status) == EXIT_FAILURE)
          Log("###Centipede fork returned EXIT_FAILURE\n");
        else
          Log("###Centipede fork returned unknown failure status\n");
      } else {
        Log("###Centipede fork crashed\n");
      }
      Log("###Centipede fork writing status to pipe1\n");
      if (write(pipe1, &status, sizeof(status)) == -1)
        Exit("###write to pipe1 failed\n");
    }
  }
  // The only way out of the loop is via Exit() or return.
  __builtin_unreachable();
}

}  // namespace centipede
