#include "help.h"

#include <stdio.h>
#include <string.h>

#include "googletest/include/gtest/gtest.h"

namespace blender {
namespace {

TEST(Help, Parse) {
  const char* input = R"(
-flag1
  --flag2= description
    --flag3: description
    --flag4: description type: bool
    --flag5
      type: string; something else
    --flag6
      default: true
    -flag7: default: "true";
    --flag8: description
      --flag7 should be used instead; default: true;
    --flag9 type: double
    --flag10 description type: int32
    --flag11 description type: uint64
    --flag12 description
      default: 10
    --flag13 descriptios
      default: -10
    --flag14 default: false
  -b, -m                      Ignored for compatibility.
  -B, --always-make           Unconditionally make all targets.
  --debug[=FLAGS]             Print various types of debugging information.
  -E STRING, --eval=STRING    Evaluate STRING as a makefile statement.
  -f FILE, --file=FILE, --makefile=FILE
  -I DIRECTORY, --include-dir=DIRECTORY
  -j [N], --jobs[=N]          Allow N jobs at once; infinite jobs with no arg.
  -O[TYPE], --output-sync[=TYPE] Synchronize output.
  -F, --fixed-strings       PATTERNS are strings
  -e, --regexp=PATTERNS     use PATTERNS for matching
  -f, --file=FILE           take PATTERNS from FILE
  -m, --max-count=NUM       stop after NUM selected lines
  -n, --line-number         print line number with output lines
      --line-buffered       flush output on every line
  -h, --no-filename         suppress the file name prefix on output
      --label=LABEL         use LABEL as the standard input file name prefix
  -d, --directories=ACTION  how to handle directories;
      --include=GLOB        search only files that match GLOB (a file pattern)
  -B, --before-context=NUM  print NUM lines of leading context
  -###                    Print (but do not run) the commands
  --amdgpu-arch-tool=<value>
  --analyzer-output <value>
  -b <arg>                Pass -b <arg> to the linker on AIX (only).
  -cxx-isystem <directory>
  -D <macro>=<value>      Define <macro> to <value> (or 1 if <value> omitted)
  -Wa,<arg>               Pass <arg> to the assembler
usage: sshd [-4Dd] [-C connection_spec] [-c host_cert_file]
            [-E log_file] [-f config_file] [-g login_grace_time]
            [-h host_key_file] [-o option] [-p port] [-u len]
usage: ssh [-@4A] [-B bind_interface]
           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]
 -:, --next               Make next URL use its separate set of options
 -#, --progress-bar       Display transfer progress as a bar
)";
  const Flag want[] = {
      // absl
      {"-flag1", kFlagUnknown},
      {"--flag2", kFlagUnknown},
      {"--flag3", kFlagUnknown},
      {"--flag4", kFlagBool},
      {"--flag5", kFlagString},
      {"--flag6", kFlagBool},
      {"-flag7", kFlagString},
      {"--flag8", kFlagBool},
      {"--flag9", kFlagDouble},
      {"--flag10", kFlagInt},
      {"--flag11", kFlagInt},
      {"--flag12", kFlagInt},
      {"--flag13", kFlagInt},
      {"--flag14", kFlagBool},
      // make
      {"-b", kFlagUnknown},
      {"-B", kFlagUnknown},
      {"--debug", kFlagUnknown},
      {"-E", kFlagUnknown},
      {"-f", kFlagUnknown},
      {"-I", kFlagUnknown},
      {"-j", kFlagUnknown},
      {"-O", kFlagUnknown},
      // grep
      {"-F", kFlagUnknown},
      {"-e", kFlagUnknown},
      {"-f", kFlagUnknown},
      {"-m", kFlagUnknown},
      {"-n", kFlagUnknown},
      {"-h", kFlagUnknown},
      {"-d", kFlagUnknown},
      {"-B", kFlagUnknown},
      // clang
      {"-###", kFlagUnknown},
      {"--amdgpu-arch-tool", kFlagUnknown},
      {"--analyzer-output", kFlagUnknown},
      {"-b", kFlagUnknown},
      {"-cxx-isystem", kFlagUnknown},
      {"-D", kFlagUnknown},
      {"-Wa,", kFlagUnknown},
      // ssh/sshd
      {"-4", kFlagBinary},
      {"-D", kFlagBinary},
      {"-d", kFlagBinary},
      {"-C", kFlagUnknown},
      {"-c", kFlagUnknown},
      {"-E", kFlagUnknown},
      {"-f", kFlagUnknown},
      {"-g", kFlagUnknown},
      {"-h", kFlagUnknown},
      {"-o", kFlagUnknown},
      {"-p", kFlagUnknown},
      {"-u", kFlagUnknown},
      {"-@", kFlagBinary},
      {"-4", kFlagBinary},
      {"-A", kFlagBinary},
      {"-B", kFlagUnknown},
      {"-b", kFlagUnknown},
      {"-c", kFlagUnknown},
      {"-D", kFlagUnknown},
      // curl
      {"-:", kFlagUnknown},
      {"-#", kFlagUnknown},
  };
  FILE* stream = fmemopen(const_cast<char*>(input), strlen(input), "r");
  auto flags = ExtractFlagsStream(stream, true);
  printf("parsed:\n");
  for (size_t i = 0; i < flags.size(); ++i)
    printf("\t{\"%s\", %s},\n", flags[i].name.c_str(),
           FlagTypeName(flags[i].type));
  ASSERT_EQ(flags.size(), sizeof(want) / sizeof(want[0]));
  for (size_t i = 0; i < flags.size(); ++i) {
    EXPECT_EQ(flags[i].name, want[i].name);
    EXPECT_EQ(flags[i].type, want[i].type) << flags[i].name;
  }
}

}  // namespace
}  // namespace blender
