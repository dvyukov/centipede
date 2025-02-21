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

#include "./minimize_crash.h"

#include <cstdlib>
#include <filesystem>  // NOLINT

#include "googlemock/include/gmock/gmock.h"
#include "googletest/include/gtest/gtest.h"
#include "./defs.h"
#include "./test_util.h"
#include "./util.h"

namespace centipede {
namespace {

// A mock for CentipedeCallbacks.
class MinimizerMock : public CentipedeCallbacks {
 public:
  MinimizerMock(const Environment &env) : CentipedeCallbacks(env) {}

  // Runs FuzzMe() on every input, imitates faulure if FuzzMe() returns true.
  bool Execute(std::string_view binary, const std::vector<ByteArray> &inputs,
               BatchResult &batch_result) override {
    batch_result.ClearAndResize(inputs.size());
    for (auto &input : inputs) {
      if (FuzzMe(input)) {
        batch_result.exit_code() = EXIT_FAILURE;
        return false;
      }
      ++batch_result.num_outputs_read();
    }
    return true;
  }

  // Runs simple mutations.
  void Mutate(const std::vector<ByteArray> &inputs, size_t num_mutants,
              std::vector<ByteArray> &mutants) override {
    byte_array_mutator_.MutateMany(inputs, num_mutants, mutants);
  }

 private:
  // Returns true on inputs that look like 'f???u???z', false otherwise.
  // The minimal input on which this function returns true is 'fuz'.
  bool FuzzMe(ByteSpan data) {
    if (data.empty()) return false;
    if (data.front() == 'f' && data[data.size() / 2] == 'u' &&
        data.back() == 'z') {
      return true;
    }
    return false;
  }
};

// Factory that creates/destroys MinimizerMock.
class MinimizerMockFactory : public CentipedeCallbacksFactory {
 public:
  CentipedeCallbacks *create(const Environment &env) override {
    return new MinimizerMock(env);
  }
  void destroy(CentipedeCallbacks *cb) override { delete cb; }
};

TEST(MinimizeTest, MinimizeTest) {
  ScopedTempDir tmp_dir;
  Environment env;
  env.workdir = tmp_dir.path;
  env.num_runs = 100000;
  MinimizerMockFactory factory;

  // Test with a non-crashy input.
  EXPECT_EQ(MinimizeCrash({1, 2, 3}, env, factory), EXIT_FAILURE);

  ByteArray expected_minimized = {'f', 'u', 'z'};

  // Test with a crashy input that can't be minimized further.
  EXPECT_EQ(MinimizeCrash(expected_minimized, env, factory), EXIT_FAILURE);

  // Test the actual minimization.
  ByteArray original_crasher = {'f', '.', '.', '.', '.', '.', '.', '.',
                                '.', '.', '.', 'u', '.', '.', '.', '.',
                                '.', '.', '.', '.', '.', '.', 'z'};
  EXPECT_EQ(MinimizeCrash(original_crasher, env, factory), EXIT_SUCCESS);
  // Collect the new crashers from the crasher dir.
  std::vector<ByteArray> crashers;
  for (auto const &dir_entry :
       std::filesystem::directory_iterator{env.MakeCrashReproducerDirPath()}) {
    ByteArray crasher;
    const std::string &path = dir_entry.path();
    ReadFromLocalFile(path, crasher);
    EXPECT_LT(crasher.size(), original_crasher.size());
    crashers.push_back(crasher);
  }
  EXPECT_THAT(crashers, testing::Contains(expected_minimized));
}

}  // namespace
}  // namespace centipede
