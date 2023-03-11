# Blender: Automatic whole-program fuzzing

`Blender` is a new type of fuzzer that does not require writing the fuzz target function,
instead it accepts the binary one wants to test as is (ideally compiled with
sanitizers and coverage, but no source code changes). This is intended to solve
one of the main problems with fuzzing -- **scalability**.

Currently to fuzz something a human expert first needs to identify that something
should be fuzzed, then write a good realistic fuzz target, and then maintain it.
As the result, fuzzing is frequently not used or not used enough in large code bases.
With `Blender` it becomes possible to fuzz e.g. **all** buildable binaries on github (*sic!*).

There is some research in the area of automatic fuzz target generation that aims at
solving this scalability problem (
[[1]](https://www.usenix.org/system/files/sec20fall_ispoglou_prepub.pdf),
[[2]](https://www.sec.in.tum.de/i20/student-work/automated-fuzz-target-generation-for-c-libraries),
[[3]](https://arxiv.org/pdf/1907.12214.pdf),
[[4]](https://ieeexplore.ieee.org/document/9693749)).
However, it suffers from the same problems as most static analysis approaches:
it can generate incorrect fuzz target code that will produce false positive
bugs, which then again human experts need to spend time on to debug and understand.
False positives may be due to incorrect arguments (for example, a function
accepts a limited range of values for an int), incorrect order of method calls,
implicit dependencies (some global state is initialized), etc.
Moreover, these auto-generated fuzz targets generally still produce additional
burden on human experts (code review and maintanance).

`Blender` solves this problem by using a dynamic approach.
The only requried input is the binary that needs to be tested.
The binary provides a superset of coverage of all possible individual fuzz
targets that can be written for the involved code. Moreover, this approach provides
high fidelity (even manually written fuzz targets can contain bugs).
Since `Blender` tests only the production code and in the exact production configuration,
it reports only bugs that affect production. The additional advantage is that
`Blender` also tests all of the "glue" code that would probably never be covered with
fuzzing otherwise (does not have really separable "inputs" in the traditional
sense, does not look important enough on its own, mostly just connects other larger
components, etc).

## The Algorithm

The insight is that any binary communicates with the environment only via system calls.
Most notably, it reads/writes local files and sends/receives network data.
Plus there are special initial inputs in the form of command line arguments `argv`
and environment variables `envp`. System calls is a boundary that is well suited
for programmatic interception and interference. High-level algorithm is as follows:
we ignore all outputs of the program (data written to disk/network) and provide
random data into the inputs (data read from disk/network).

For example:

 - `open("/what/ever")` -> do nothing and give the program a random fd 1234
 - `write(1234, data, 100)` -> do nothing and return 100 to the program
 - `read(1234, data, 100)` <- return 50 random bytes

However, one complication is how to make such a fuzzer really smart and achieve deep coverage.
The good news is that all existing tricks used in fuzzing still work.
In particular we can:

 - use code coverage as feedback
 - use dataflow analysis
 - use symbolic/concolic execution
 - intercept str/mem* functions and comparison operands
 - use heuristics (we know syscall semantics)
 - trace actual executions and use them as seeds
 - use machine learning

Another complication is how to target it at finding more important bugs
(it can find too many!). Some ideas include:

 - mess less with argv/envp
 - mess less with file contents, mess more with network
 - use allow/blocklists to tune what to mess with

However, note that, for example, for setuid binaries any vector is critical
(even completley insane envp).

Note that generally it's not safe to run a random unknown binary
(it can format disk, remove files, etc). The second important role
of the system call interception is *isolation*. Under `Blender` the binary
is completely sandboxed and does not produce any effect on the real world.
This makes it safe to run random binaries with random inputs.

## Prototype

The current prototype works in the following way.
We intercept execution early via .preinit_array/constructor.
Then for each test case:

 - generate random argv/envp
 - [reexec](https://man7.org/linux/man-pages/man2/execve.2.html)
 - intercept and spoof system call results

System call interception during test execution is done using
[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html).
We have own system call implementation that is not intercepted,
so we can execute real system calls when needed.

The prototype can work in 2 modes: *stand-alone* (generates inputs
using `rand()`) and integrated with `Centipede` fuzzer
(uses randomness provided by the fuzzer engine).
The prototype can be either linked into the target program
or LD_PRELOAD-ed, see [Usage](#Usage) section for details.

Two additional interesting aspects were revealed by the prototype.
First, we can mess with some data returned from system calls,
but not with all data. We still need to ensure basic data consistency
guaranteed by the kernel. For example, `clock_gettime` and `stat`
system calls return number of nanoseconds and that value must be
less than 1e9. Larger values mean a broken kernel and programs
generally shouldn't and can't protect from a broken kernel.
Similarly, we can't pretend that a `read` system call returns
more data than the provided buffer.

Second, the bug oracle becomes tricky. We cannot simply look
for non-0 exit status, the program will fial a lot since we give
it garbage. A trivial example is failing on incorrect command line flags.
We still can look for [Sanitizers](https://clang.llvm.org/docs/AddressSanitizer.html)
bug reports since that inevitably means undefined behavior.
We also look for `abort` calls (the program sending `SIGABRT` to itself).
We also can easily grep the program output for particular patterns
since we intercept the corresponding system calls. However, we still
cannot automatically detect all bugs (for example, if the program
has a custom assert/bug detector that prints something and calls `exit(1)`).

## Future Work

A lot.

The current state is a proof-of-concent prototype that works and
[finds bugs](#Trophies), but needs more work. Contributions are welcome.

Some known areas for improvement:

 - encode/mutate inputs in structured form (syscall number, results)
 - handle multiple threads (serialize? store tids in the input?)
 - remove other source of non-determinism (virtualize time, pids/uids)
 - better isolation (currently not 100% bullet-proof)
 - take snapshots during execution (faster and solves determinism)
 - handle more system calls
 - handle system calls better (heuristics for return values, failures)
 - terminate https and provide support for other common protocols
 - better kernel model (e.g. one false positive was due to incorrect netlink messages)
 - better bug oracle (is abort a bug or not? what other oracles we can use?)
 - implement tracing to obtain corpus seeds
 - find what env vars to pass (intercept getenv)
 - test and provide better support for other than C/C++ languages
 - add tests

## Trophies

Currently `Blender` is not very smart and it was applied to few programs,
so the list is not very large.

One of the targets used for `Blender` testing was `clang` compiler,
where 12 bugs were detected. One particularly interesting relates
to parsing of installed CUDA header files.

To reproduce (ensure you don't have `/usr/local/cuda` and remove it afterwards):

```
sudo mkdir -p /usr/local/cuda/{include,bin,lib,lib64,nvvm/libdevice}
echo -n 1 | sudo tee /usr/local/cuda/include/cuda.h
sudo chmod -R a+x /usr/local/cuda/

clang -v
clang version 17.0.0 (291c390e37e4405e2842d740fcc67eae5769fb88)
...
clang: llvm/include/llvm/ADT/StringRef.h:598:
  llvm::StringRef llvm::StringRef::drop_front(size_t) const:
  Assertion `size() >= N && "Dropping more elements than exist"' failed.
Stack dump:
0.	Program arguments: clang -v
1.	Compilation construction
 #6 0x00007fdeee045472 abort ./stdlib/abort.c:81:7
 #9 0x0000555f7e8cedac clang::driver::CudaInstallationDetector::CudaInstallationDetector
#10 0x0000555f7e91f7f4 clang::driver::toolchains::Generic_GCC::printVerboseInfo
#14 0x0000555f7bb53be1 main
```

The bug happens
[here](https://github.com/llvm/llvm-project/blob/291c390e37e4405e2842d740fcc67eae5769fb88/clang/lib/Driver/ToolChains/Cuda.cpp#L103)
when `find_first_of` returns -1.

If we put aside criticality of this bug for the humanity, it's a memory-corrupting
bug in a relatively typical fuzzing target (file format parser).
But more importantly it was found without any knowledge that this parser
exists in the program (did you know that `clang -v` tries to open and parse
CUDA headers?) and on a system that does not even have these files installed.

Other bugs found:

```
$ clang -Wp,
clang: SmallVector.h:298: SmallVector::operator[](...):
Assertion `idx < size()' failed.
 #6 0x7f0466a45472 abort
#10 0x55c8f2ce1a26 clang::driver::Driver::BuildCompilation(...)
#11 0x55c8f0033ae1 clang_main(...)
```

```
$ clang -ftrivial-auto-var-init-stop-after=* -
terminate called after throwing an instance of 'std::invalid_argument'
```

as well as:

```
FileSystem.h:117:57: runtime error: load of value 384, which is not a valid value for type 'llvm::sys::fs::perms'
Program.inc:71: llvm::sys::findProgramByName(...): Assertion `!Name.empty() && "Must have a name!"' failed.
FrontendAction.cpp:748: clang::FrontendAction::BeginSourceFile(...): Assertion `hasIRSupport() && "This action does not have IR file support!"'
SerializedDiagnosticPrinter.cpp:813: SDiagsWriter::finish(): Assertion `!OS->has_error()' failed.
MemoryBuffer.cpp:373: shouldUseMmap(...): Assertion `End <= FileSize' failed.
OptTable.cpp:232: OptTable::findNearest(...): Assertion `!Option.empty()' failed.
terminate called after throwing an instance of 'std::invalid_argument'
pure virtual method called
```

OOB in `bash ec8113b98613`:

```
AddressSanitizer: heap-buffer-overflow on address 0x611000005a00 at pc 0x561e89fa814a bp 0x7ffea2a828b0 sp 0x7ffea2a828a8
READ of size 1 at 0x611000005a00 thread T0
    #0 history_expand lib/readline/histexpand.c:1003:9
    #1 pre_process_line bashhist.c:580:18
    #2 shell_getc parse.y:2485:17
    #3 read_token parse.y:3402:23
    #4 yylex parse.y:2890:19
    #5 yyparse y.tab.c:1854:16
    #6 parse_command eval.c:348:7
    #7 read_command eval.c:392:12
    #8 reader_loop eval.c:139:11
    #9 main shell.c:833:3

0x611000005a00 is located 0 bytes after 256-byte region [0x611000005900,0x611000005a00)
allocated by thread T0 here:
    #0 malloc
    #1 xrealloc xmalloc.c:135:47
    #2 shell_getc parse.y:2436:6
    #3 read_token parse.y:3402:23
    #4 yylex parse.y:2890:19
    #5 yyparse y.tab.c:1854:16
    #6 parse_command eval.c:348:7
    #7 read_command eval.c:392:12
    #8 reader_loop eval.c:139:11
    #9 main shell.c:833:3

SUMMARY: AddressSanitizer: heap-buffer-overflow (bash.asan+0x224a149)
Shadow bytes around the buggy address:
  0x611000005780: fa fa fa fa fa fa fa fa fd fd fd fd fd fd fd fd
  0x611000005800: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x611000005880: fd fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa
  0x611000005900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x611000005980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x611000005a00:[fa]fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x611000005a80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x611000005b00: 00 00 00 00 00 00 00 00 fa fa fa fa fa fa fa fa
  0x611000005b80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x611000005c00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x611000005c80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
```

`Blender` rediscovered
[OOB in env var parsing](https://github.com/mirror/make/commit/950f3d305f6693460e87b9a9b50f1d31714eb54d)
in `make`.

Found an int overflow in ELF parser (happened when
a program tried to print a stack trace for another condition and tried
to open and parse own binary to print the stack trace); and a bunch
of incorrect handling of system call errors (ENOMEM, EINTR)
working as a fault-injection tool.

All bugs listed in the recent article
[cURL audit: How a joke led to significant findings](https://blog.trailofbits.com/2023/02/14/curl-audit-fuzzing-libcurl-command-line-interface/)
were not found by `Blender`, but should be findable with no additional work
(you just throw `cURL` binary into `Blender`).

## Usage

`Blender` has 2 operation modes:

### Stand-alone

In this mode the binary is executed once in a random manner.

First, build `Blender`:

```
bazel build -c opt blender:all
```

Build the target binary with some additional flags (in this case bash):

```
git clone https://git.savannah.gnu.org/git/bash.git
cd bash
CC=clang CFLAGS="-fsanitize=address,undefined -g" ./configure --with-bash-malloc=no
make -j10
```

Run the binary with `Blender` (it is fuzzed as it runs):

```
LD_PRELOAD=bazel-bin/blender/blender.so /bash/bash
```

Here we used the LD_PRELOAD-ed version, if you can link an additional
library into the binary, then you can link in `bazel-bin/blender/libblender.pic.lo`
instead.

If no bug is detected, it will print nothing and exit with 0 status (no normal
output and status). If a bug is detected, a bug report is printed and it exits
with non-0 status.

The stand-alone mode is useful for development of the blender itself, but can be
used with the stress utility as a poormans fuzzer:

```
go get golang.org/x/tools/cmd/stress
LD_PRELOAD=bazel-bin/blender/blender.so stress /bash/bash
```

Crashes can be reproduced using `BLENDER_SEED` env var (see below), assuming the
target is deterministic (single-threaded).

Useful environment variables for development:

-   `BLENDER_LOG=1` print debug output
-   `BLENDER_LOG=2` print more debug output
-   `BLENDER_SEED=NNN` re-run the given sees (the seed is printed on bugs)
-   `BLENDER_OUTPUT=1` print normal program output even if no bug is detected
-   `BLENDER_DISABLE=1` disable blender interference

### Centipede

In this mode the binary will be tested in a loop using
[Centipede](https://github.com/google/centipede).

First, build `Centipede` and `Blender`:

```
bazel build -c opt :all blender:all
```

Then, build the target binary with few additional flags:

```
CC=clang CFLAGS="-fsanitize=address,undefined -g -fno-builtin -fsanitize-coverage=trace-pc-guard,pc-table,trace-cmp" \
  LDFLAGS="-lstdc++ -Wl,--whole-archive /centipede/bazel-bin/blender/libblender.pic.lo -Wl,--no-whole-archive \
  /centipede/bazel-bin/blender/liblib.a /centipede/bazel-bin/libcentipede_runner_no_main.a" \
  ./configure --with-bash-malloc=no
BLENDER_DISABLE=1 make -j10
```

Run `Centipede`:

```
mkdir /tmp/workdir
bazel-bin/centipede --workdir /tmp/workdir --batch_size=10 --max_len=65536 --timeout=60 --timeout_per_batch=600 --shmem_size_mb=4096 --binary /bash/bash
```

Note: the execution is quite slow now, so we use small batch size and increased timeout.
Also `Blender` currently needs very large inputs. Other useful `Centipede`
flags: `-j=NUM_CPU` and `--exit_on_crash`.

Crashes can be reproduced by passing the input to the binary as an argument
(again assuming it's deterministic and single-threaded):

```
blaze-bin/third_party/llvm/llvm-project/clang/clang /tmp/workdir/crashes/xxxxx
```

### Coverage Reports

To generate
[clang coverage reports](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html)
for stand-alone more build the binary as:

```
bazel build -c opt blender:all --copt -DBLENDER_LLVM_COVERAGE=1
CC=clang CFLAGS="-fprofile-instr-generate -fcoverage-mapping -g" LDFLAGS="-lstdc++ -Wl,--whole-archive \
  /centipede/bazel-bin/blender/libblender.pic.lo -Wl,--no-whole-archive /centipede/bazel-bin/blender/liblib.a \
  /centipede/bazel-bin/libcentipede_runner_no_main.a" ./configure --with-bash-malloc=no
BLENDER_DISABLE=1 make -j10
cp bash bash.cov
```

Collect the profile with:

```
LLVM_PROFILE_FILE=/tmp/profraw ./bash.cov
```

Render the report:

```
llvm-profdata merge -sparse /tmp/profraw -o /tmp/profdata
llvm-cov show -format=html bash.cov -instr-profile=/tmp/profdata -output-dir=/tmp/report/
xdg-open /tmp/report/index.html
```

Or with the stress utility:

```
LLVM_PROFILE_FILE=/tmp/profraw_%72m stress ./bash.cov
llvm-profdata merge -sparse /tmp/profraw_* -o /tmp/profdata
```

For `Centipede` run it as:

```
bazel-bin/centipede --workdir /tmp/workdir --batch_size=10 --max_len=65536 --timeout=60 --timeout_per_batch=600 \
  --shmem_size_mb=4096 --address_space_limit_mb=32768 --binary /bash/bash.asan --clang_coverage_binary /bash/bash.cov
```
