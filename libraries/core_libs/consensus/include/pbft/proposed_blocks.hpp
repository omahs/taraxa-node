#pragma once

#include <map>
#include <optional>
#include <shared_mutex>

#include "common/types.hpp"
#include "storage/storage.hpp"

namespace taraxa {

class PbftBlock;
class Vote;

/**
 * @brief class ProposedBlocks holds proposed pbft blocks together with propose votes hashes per period & round
 */
class ProposedBlocks {
 public:
  ProposedBlocks(std::shared_ptr<DbStorage> db) : db_(db) {}

  /**
   * @brief Push proposed PBFT block into the proposed blocks
   * @param proposed_block proposed PBFT block
   * @param propose_vote propose PBFT vote
   * @return true if block was successfully pushed, otherwise false
   */
  bool pushProposedPbftBlock(const std::shared_ptr<PbftBlock>& proposed_block,
                             const std::shared_ptr<Vote>& propose_vote);

  /**
   * @brief Push proposed PBFT block into the proposed blocks
   * @param round
   * @param proposed_block
   * @param save_to_db if true save to db
   * @return true if block was successfully pushed, otherwise false
   */
  bool pushProposedPbftBlock(PbftRound round, const std::shared_ptr<PbftBlock>& proposed_block, bool save_to_db = true);

  /**
   * @brief Mark block as valid - no need to validate it again
   *
   * @param round
   * @param proposed_block
   */
  void markBlockAsValid(PbftRound round, const std::shared_ptr<PbftBlock>& proposed_block);

  /**
   * @brief Get a proposed PBFT block based on specified period, round and block hash
   * @param period
   * @param round
   * @param block_hash
   * @return optional<pair<block, is_valid flag>>
   */
  std::optional<std::pair<std::shared_ptr<PbftBlock>, bool>> getPbftProposedBlock(PbftPeriod period, PbftRound round,
                                                                                  const blk_hash_t& block_hash) const;

  /**
   * @brief Check if specified block is already in proposed blocks
   * @param period
   * @param round
   * @param block_hash
   * @return true if block is present, otherwise false
   */
  bool isInProposedBlocks(PbftPeriod period, PbftRound round, const blk_hash_t& block_hash) const;

  /**
   * @brief Cleanup all proposed PBFT blocks for the finalized period
   * @param period
   */
  void cleanupProposedPbftBlocksByPeriod(PbftPeriod period);

  /**
   * @brief Cleanup all proposed PBFT blocks for the finalized round - 1. We must keep previous round proposed blocks
   *        for voting purposes
   * @param period
   * @param round
   */
  void cleanupProposedPbftBlocksByRound(PbftPeriod period, PbftRound round);

 private:
  // <PBFT period, <PBFT round, <block hash, [block, is_valid_flag]>>>
  std::map<PbftPeriod, std::map<PbftRound, std::unordered_map<blk_hash_t, std::pair<std::shared_ptr<PbftBlock>, bool>>>>
      proposed_blocks_;
  mutable std::shared_mutex proposed_blocks_mutex_;
  std::shared_ptr<DbStorage> db_;
};

}  // namespace taraxa