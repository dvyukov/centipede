#include <stdlib.h>
#include <unistd.h>

#include "common.h"

extern "C" {
int CentipedeRunnerMain(
    int argc, char** argv,
    int (*test_one_input_cb)(const char* data, size_t size),
    int (*initialize_cb)(int* argc, char*** argv),
    size_t (*custom_mutator_cb)(uint8_t* data, size_t size, size_t max_size,
                                unsigned int seed),
    size_t (*custom_crossover_cb)(const uint8_t* data1, size_t size1,
                                  const uint8_t* data2, size_t size2,
                                  uint8_t* out, size_t max_out_size,
                                  unsigned int seed));
void CentipedeCollectCoverage(int exit_status);
int CentipedeManualCoverage() { return 1; }
}

namespace blender {

void MaybeCentipedeMain(int argc, char** argv,
                        int (*test_cb)(const char* data, size_t size)) {
  if (getenv("CENTIPEDE_RUNNER_FLAGS"))
    _exit(CentipedeRunnerMain(argc, argv, test_cb, nullptr, nullptr, nullptr));
}

void CentipedeDumpCoverage() {
  if (getenv("CENTIPEDE_RUNNER_FLAGS")) CentipedeCollectCoverage(0);
}

}  // namespace blender
