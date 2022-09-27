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

#include "./environment.h"

#include "googletest/include/gtest/gtest.h"

namespace centipede {

TEST(Environment, UpdateForExperiment) {
  Environment env;
  env.num_threads = 12;
  env.experiment = "use_cmp_features=false,true:path_level=10,20,30";

  auto Experiment = [&](size_t shard_index, bool val1, size_t val2,
                        std::string_view experiment_name) {
    env.my_shard_index = shard_index;
    env.UpdateForExperiment();
    EXPECT_EQ(env.load_other_shard_frequency, 0);
    EXPECT_EQ(env.use_cmp_features, val1);
    EXPECT_EQ(env.path_level, val2);
    EXPECT_EQ(env.experiment_name, experiment_name);
  };

  Experiment(0, false, 10, "E00");
  Experiment(1, false, 20, "E01");
  Experiment(2, false, 30, "E02");
  Experiment(3, true, 10, "E10");
  Experiment(4, true, 20, "E11");
  Experiment(5, true, 30, "E12");
  Experiment(6, false, 10, "E00");
  Experiment(7, false, 20, "E01");
  Experiment(8, false, 30, "E02");
  Experiment(9, true, 10, "E10");
  Experiment(10, true, 20, "E11");
  Experiment(11, true, 30, "E12");
}

}  // namespace centipede
