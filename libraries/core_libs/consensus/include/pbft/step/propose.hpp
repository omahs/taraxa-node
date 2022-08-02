#pragma once
#include "logger/logger.hpp"
#include "pbft/step/step.hpp"

namespace taraxa::step {

class Propose : public Step {
 public:
  Propose(std::shared_ptr<RoundFace> round) : Step(StepType::propose, std::move(round)) { init(); }
  void run() override;

 private:
  void init() override {}
  /**
   * @brief Propose a new PBFT block
   * @return proposed PBFT block hash
   */
  blk_hash_t proposePbftBlock_();

  /**
   * @brief Generate PBFT block, push into unverified queue, and broadcast to peers
   * @param prev_blk_hash previous PBFT block hash
   * @param anchor_hash proposed DAG pivot block hash for finalization
   * @param order_hash the hash of all DAG blocks include in the PBFT block
   * @return PBFT block hash
   */
  blk_hash_t generatePbftBlock(const blk_hash_t &prev_blk_hash, const blk_hash_t &anchor_hash,
                               const blk_hash_t &order_hash);

  void finish_() override;
  // Ensures that only one PBFT block per period can be proposed
  blk_hash_t proposed_block_hash_ = kNullBlockHash;
};

}  // namespace taraxa::step