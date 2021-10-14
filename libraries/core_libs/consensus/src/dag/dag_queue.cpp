#include "dag/dag_queue.hpp"

namespace taraxa {

size_t DagBlockQueue::size() const {
  std::shared_lock lock(queue_access_);
  return data_queue_.size();
}

void DagBlockQueue::clear(level_t lvl) {
  std::unique_lock lock(queue_access_);
  for (auto it = lvl_queue_.begin(); it != lvl_queue_.upper_bound(lvl); ++it) {
    data_queue_.erase(it->second);
    for (const auto& hash : missing_queue_[it->second]) {
      reverse_queue_.erase(hash);
    }
    missing_queue_.erase(it->second);
  }
  lvl_queue_.erase(lvl);
}

void DagBlockQueue::insert(DagBlock&& block, std::unordered_set<blk_hash_t>&& missing_blocks) {
  const auto& block_hash = block.getHash();
  std::unique_lock lock(queue_access_);
  if (data_queue_.contains(block_hash)) {
    return;
  }
  lvl_queue_.emplace(block.getLevel(), block_hash);
  for (auto const& hash : missing_blocks) {
    reverse_queue_.emplace(hash, block_hash);
  }
  data_queue_.emplace(block_hash, std::move(block));
  missing_queue_.emplace(block_hash, std::move(missing_blocks));
}

std::vector<DagBlock> DagBlockQueue::pop(const blk_hash_t& hash) {
  std::vector<DagBlock> result;
  std::unique_lock lock(queue_access_);
  if (!reverse_queue_.contains(hash)) {
    return result;
  }
  auto range = reverse_queue_.equal_range(hash);
  for (auto it = range.first; it != range.second; ++it) {
    if (missing_queue_.contains(it->second)) {
      if (missing_queue_[it->second].size() == 1) {
        missing_queue_.erase(it->second);
        result.push_back(std::move(data_queue_[hash]));
        data_queue_.erase(hash);
      } else {
        missing_queue_[it->second].erase(hash);
      }
    }
  }
  reverse_queue_.erase(hash);
  return result;
}

}  // namespace taraxa