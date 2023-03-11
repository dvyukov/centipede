#include "help.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "common.h"

namespace blender {
namespace {
std::vector<Flag> ExtractHelpFlags(const char* flag[2]) {
  int output[2];
  if (pipe(output)) FAIL("pipe failed");
  int input[2];
  if (pipe(input)) FAIL("pipe failed");
  close(input[1]);
  int pid = fork();
  if (pid < 0) FAIL("fork failed");
  if (pid == 0) {
    if (dup2(input[0], STDIN_FILENO) < 0) FAIL("dup2 failed");
    if (dup2(output[1], STDOUT_FILENO) < 0) FAIL("dup2 failed");
    if (dup2(output[1], STDERR_FILENO) < 0) FAIL("dup2 failed");
    if (syscall(SYS_close_range, STDERR_FILENO + 1, ~0u, 0))
      FAIL("close_range");
    alarm(10);
    const char* argp[] = {"/proc/self/exe", flag[0], flag[1], nullptr};
    const char* envp[] = {"BLENDER_DISABLE=1", nullptr};
    execve(argp[0], const_cast<char**>(argp), const_cast<char**>(envp));
    FAIL("execve failed");
  }
  close(input[0]);
  close(output[1]);
  FILE* stream = fdopen(output[0], "r");
  if (!stream) FAIL("fdopen failed");
  auto flags = ExtractFlagsStream(stream, !strcmp(flag[0], "--helpfull"));
  fclose(stream);
  int status = 0;
  while (waitpid(-1, &status, __WALL) != pid) {
  }
  LOG("extracted %zu flags using %s flag", flags.size(), flag[0]);
  for (auto& flag : flags)
    LOGV("  flag '%s' %s", flag.name.c_str(), FlagTypeName(flag.type));
  return flags;
}

bool IsFlagChar(char v) {
  return isalnum(v) || v == '-' || v == '_' || v == '#' || v == '@' || v == ':';
}

}  // namespace

std::vector<Flag> ExtractFlagsStream(FILE* stream, bool helpfull) {
  std::vector<Flag> flags;
  char* line = nullptr;
  size_t line_size = 0;
  while (getline(&line, &line_size, stream) > 0) {
    const char* pos = line;
    while (isblank(*pos)) pos++;
    // Flag start
    if (*pos == '-') {
      // Absl has very specific help format where position 6 means
      // start of the previous flag descriptions rather than a new flag.
      if (!helpfull || pos - line != 6) {
        const char* flag = pos;
        while (IsFlagChar(*pos)) pos++;
        // Include comma in "-Wa,<arg>".
        if (*pos == ',' && pos[1] == '<') pos++;
        // Exclude ':' at the end, probably separator before description,
        // but not if it's the only symbol (thank you, cURL).
        if (pos[-1] == ':' && pos - flag > 2) pos--;
        flags.push_back({std::string(flag, pos), kFlagUnknown});
      }
    }
    if (!strncmp(pos, "usage:", strlen("usage:")))
      while (*pos && *pos != '[') pos++;
    while (pos[0] == '[' && pos[1] == '-') {
      if (pos[3] == ' ') {
        flags.push_back({std::string(pos + 1, pos + 3), kFlagUnknown});
      } else {
        for (pos += 2; IsFlagChar(*pos); pos++)
          flags.push_back({std::string{'-', *pos}, kFlagBinary});
      }
      while (*pos && *pos != ']') pos++;
      while (*pos && *pos != '[') pos++;
    }
    auto* flag = flags.empty() ? nullptr : &flags.back();
    if (!flag || flag->type != kFlagUnknown) continue;
    // Paser absl flag descriptions to figure out the type.
    const char* type_str = "type: ";
    if (auto* type = strstr(line, type_str)) {
      type += strlen(type_str);
      if (!strncmp(type, "string", strlen("string")))
        flag->type = kFlagString;
      else if (!strncmp(type, "double", strlen("double")))
        flag->type = kFlagDouble;
      else if (!strncmp(type, "bool", strlen("bool")))
        flag->type = kFlagBool;
      else if (!strncmp(type, "int", strlen("int")))
        flag->type = kFlagInt;
      else if (!strncmp(type, "uint", strlen("uint")))
        flag->type = kFlagInt;
    }
    const char* default_str = "default: ";
    if (auto* dflt = strstr(line, default_str)) {
      switch (dflt[strlen(default_str)]) {
        case '"':
          flag->type = kFlagString;
          break;
        case 't':
        case 'f':
          flag->type = kFlagBool;
          break;
        case '-':
        case '0' ... '9':
          flag->type = kFlagInt;
          break;
      }
    }
  }
  free(line);
  return flags;
}

std::vector<Flag> ExtractHelpFlags() {
  const char* flags[][2] = {
      {"--helpfull"}, {"--help", "all"}, {"--help"}, {"-h"}};
  for (auto flag : flags) {
    auto res = ExtractHelpFlags(flag);
    if (!res.empty()) return res;
  }
  return {};
}

const char* FlagTypeName(FlagType type) {
  switch (type) {
    case kFlagUnknown:
      return "kFlagUnknown";
    case kFlagBinary:
      return "kFlagBinary";
    case kFlagString:
      return "kFlagString";
    case kFlagDouble:
      return "kFlagDouble";
    case kFlagBool:
      return "kFlagBool";
    case kFlagInt:
      return "kFlagInt";
  }
  FAIL("unknown flag type %d", type);
}

__attribute__((init_priority(119))) std::vector<Flag> program_flags;

}  // namespace blender