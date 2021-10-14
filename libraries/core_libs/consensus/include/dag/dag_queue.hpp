#pragma once

#include <shared_mutex>

#include "dag/dag_block.hpp"

namespace taraxa {

class DagBlockQueue {
 public:
  DagBlockQueue() = default;

  void insert(DagBlock &&block, std::unordered_set<blk_hash_t> &&missing_blocks);
  std::vector<DagBlock> pop(const blk_hash_t &hash);
  void clear(level_t lvl);
  size_t size() const;

 private:
  std::multimap<level_t, blk_hash_t> lvl_queue_;
  std::unordered_map<blk_hash_t, DagBlock> data_queue_;
  std::unordered_multimap<blk_hash_t, blk_hash_t> reverse_queue_;
  std::unordered_map<blk_hash_t, std::unordered_set<blk_hash_t>> missing_queue_;
  mutable std::shared_mutex queue_access_;
};

}  // namespace taraxa