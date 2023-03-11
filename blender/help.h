#ifndef BLENDER_HELP_H_
#define BLENDER_HELP_H_

#include <stdio.h>

#include <string>
#include <vector>

namespace blender {

enum FlagType {
  kFlagUnknown,
  kFlagBinary,
  kFlagString,
  kFlagDouble,
  kFlagBool,
  kFlagInt,
  kFlagTypeLast = kFlagInt,
};

struct Flag {
  std::string name;
  FlagType type;
};

std::vector<Flag> ExtractHelpFlags();
std::vector<Flag> ExtractFlagsStream(FILE* stream, bool helpfull);
const char* FlagTypeName(FlagType type);

extern std::vector<Flag> program_flags;

}  // namespace blender

#endif  // BLENDER_HELP_H_
