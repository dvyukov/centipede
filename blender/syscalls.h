#ifndef BLENDER_SYSCALLS_H_
#define BLENDER_SYSCALLS_H_

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common.h"

namespace blender {

constexpr uptr kSyscallArgs = 6;

using Result = std::optional<uptr>;

void SetRandomSeed(uptr seed);
void SetRandomData(const char* data, uptr size);
std::optional<uptr> GetOriginalRandomSeed();
std::pair<const void*, uptr> GetRemainingRandomData();

Result HandleSyscall(const uptr pc, const uptr nr, uptr args[kSyscallArgs]);

std::vector<std::string> GenerateArgv();
std::vector<std::string> GenerateEnv();

}  // namespace blender

#endif  // BLENDER_SYSCALLS_H_
