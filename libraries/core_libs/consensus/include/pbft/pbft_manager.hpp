#pragma once

#include <string>
#include <thread>

#include "common/types.hpp"
#include "common/vrf_wrapper.hpp"
#include "config/config.hpp"
#include "final_chain/final_chain.hpp"
#include "key_manager/key_manager.hpp"
#include "logger/logger.hpp"
#include "network/network.hpp"
#include "network/tarcap/taraxa_capability.hpp"
#include "pbft/period_data_queue.hpp"
#include "pbft/proposed_blocks.hpp"
#include "pbft/soft_voted_block_data.hpp"

#define NULL_BLOCK_HASH blk_hash_t(0)
#define POLLING_INTERVAL_ms 100  // milliseconds...
#define MAX_STEPS 13             // Need to be a odd number

namespace taraxa {

/** @addtogroup PBFT
 * @{
 */

class FullNode;

enum PbftStates { value_proposal_state = 1, filter_state, certify_state, finish_state, finish_polling_state };

/**
 * @brief PbftManager class is a daemon that is used to finalize a bench of directed acyclic graph (DAG) blocks by using
 * Practical Byzantine Fault Tolerance (PBFT) protocol
 *
 * According to paper "ALGORAND AGREEMENT Super Fast and Partition Resilient Byzantine Agreement
 * (https://eprint.iacr.org/2018/377.pdf)", implement PBFT manager for finalizing DAG blocks.
 *
 * There are 5 states in one PBFT round: proposal state, filter state, certify state, finish state, and finish polling
 * state.
 * - Proposal state: PBFT step 1. Generate a PBFT block and propose a vote on the block hash
 * - Filter state: PBFT step 2. Identify a leader block from all received proposed blocks for the current period by
 * using minimum Verifiable Random Function (VRF) output. Soft vote at the leader block hash. In filter state, don’t
 * need check vote value correction.
 * - Certify state: PBFT step 3. If receive enough soft votes, cert vote at the value. If receive enough cert votes,
 * finalize the PBFT block and push it to PBFT chain.
 * - Finish state: Happens at even number steps from step 4. Next vote at finishing value for the current PBFT round. If
 * node receives enough next voting votes, PBFT goes to next round.
 * - Finish polling state: Happens at odd number steps from step 5. Next vote at finishing value for the current PBFT
 * round. If node receives enough next voting votes, PBFT goes to next round.
 *
 * PBFT timing: All players keep a timer clock. The timer clock will reset to 0 at every new PBFT round. That doesn’t
 * require all players clocks to be synchronized; it only requires that they have the same clock speed.
 * - Proposal state: Reset clock to 0
 * - Filter state: Start at clock 2 lambda time
 * - Certify state: Start after filter state, clock is between 2 lambda and 4 lambda duration
 * - Finish state: Start at 4 lambda time, until receive enough next voting votes to go to next round
 * - Finish polling state: Start after first finish state. If node receives enough next voting votes within 2 lambda
 * duration, PBFT will go to next round. Otherwise that will go back to Finish state.
 */
class PbftManager : public std::enable_shared_from_this<PbftManager> {
 public:
  using time_point = std::chrono::system_clock::time_point;
  using vrf_sk_t = vrf_wrapper::vrf_sk_t;

  PbftManager(const PbftConfig &conf, const blk_hash_t &dag_genesis_block_hash, addr_t node_addr,
              std::shared_ptr<DbStorage> db, std::shared_ptr<PbftChain> pbft_chain,
              std::shared_ptr<VoteManager> vote_mgr, std::shared_ptr<NextVotesManager> next_votes_mgr,
              std::shared_ptr<DagManager> dag_mgr, std::shared_ptr<TransactionManager> trx_mgr,
              std::shared_ptr<FinalChain> final_chain, std::shared_ptr<KeyManager> key_manager, secret_t node_sk,
              vrf_sk_t vrf_sk, uint32_t max_levels_per_period = kMaxLevelsPerPeriod);
  ~PbftManager();
  PbftManager(const PbftManager &) = delete;
  PbftManager(PbftManager &&) = delete;
  PbftManager &operator=(const PbftManager &) = delete;
  PbftManager &operator=(PbftManager &&) = delete;

  /**
   * @brief Set network as a weak pointer
   * @param network a weak pinter
   */
  void setNetwork(std::weak_ptr<Network> network);

  /**
   * @brief Start PBFT daemon
   */
  void start();

  /**
   * @brief Stop PBFT daemon
   */
  void stop();

  /**
   * @brief Run PBFT daemon
   */
  void run();

  /**
   * @brief Initial PBFT states when node start PBFT
   */
  void initialState();

  /**
   * @brief Check PBFT blocks syncing queue. If there are synced PBFT blocks in queue, push it to PBFT chain
   */
  void pushSyncedPbftBlocksIntoChain();

  /**
   * @brief Get a DAG block period number
   * @param hash DAG block hash
   * @return true with DAG block period number if the DAG block has been finalized. Otherwise return false
   */
  std::pair<bool, uint64_t> getDagBlockPeriod(blk_hash_t const &hash);

  /**
   * @brief Get current PBFT period number
   * @return current PBFT period
   */
  uint64_t getPbftPeriod() const;

  /**
   * @brief Get current PBFT round number
   * @return current PBFT round
   */
  uint64_t getPbftRound() const;

  /**
   * @brief Get PBFT round & period number
   * @return <PBFT round, PBFT period>
   */
  std::pair<uint64_t, uint64_t> getPbftRoundAndPeriod() const;

  /**
   * @brief Get PBFT step number
   * @return PBFT step
   */
  uint64_t getPbftStep() const;

  /**
   * @brief Set PBFT round number
   * @param round PBFT round
   */
  void setPbftRound(uint64_t const round);

  /**
   * @brief Set PBFT step
   * @param pbft_step PBFT step
   */
  void setPbftStep(size_t const pbft_step);

  /**
   * @brief Generate PBFT block, push into unverified queue, and broadcast to peers
   * @param propose_period
   * @param prev_blk_hash previous PBFT block hash
   * @param anchor_hash proposed DAG pivot block hash for finalization
   * @param order_hash the hash of all DAG blocks include in the PBFT block
   * @return PBFT block
   */
  std::shared_ptr<PbftBlock> generatePbftBlock(uint64_t propose_period, const blk_hash_t &prev_blk_hash,
                                               const blk_hash_t &anchor_hash, const blk_hash_t &order_hash);

  /**
   * @brief Generate a vote
   * @param blockhash vote on PBFT block hash
   * @param type vote type
   * @param period PBFT period
   * @param round PBFT round
   * @param step PBFT step
   * @return vote
   */
  std::shared_ptr<Vote> generateVote(blk_hash_t const &blockhash, PbftVoteTypes type, uint64_t period, uint64_t round,
                                     size_t step);

  /**
   * @brief Get current total DPOS votes count
   * @return current total DPOS votes count if successful, otherwise (due to non-existent data for pbft_period) empty
   * optional
   */
  std::optional<uint64_t> getCurrentDposTotalVotesCount() const;

  /**
   * @brief Get current node DPOS votes count
   * @return node current DPOS votes count if successful, otherwise (due to non-existent data for pbft_period) empty
   * optional
   */
  std::optional<uint64_t> getCurrentNodeVotesCount() const;

  /**
   * @brief Get PBFT blocks synced period
   * @return PBFT blocks synced period
   */
  uint64_t pbftSyncingPeriod() const;

  /**
   * @brief Get PBFT blocks syncing queue size
   * @return PBFT syncing queue size
   */
  size_t periodDataQueueSize() const;

  /**
   * @brief Returns true if queue is empty
   * @return
   */
  bool periodDataQueueEmpty() const;

  /**
   * @brief Push synced period data in syncing queue
   * @param block synced period data from peer
   * @param current_block_cert_votes cert votes for PeriodData pbft block period
   * @param node_id peer node ID
   */
  void periodDataQueuePush(PeriodData &&period_data, dev::p2p::NodeID const &node_id,
                           std::vector<std::shared_ptr<Vote>> &&current_block_cert_votes);

  /**
   * @brief Get last pbft block hash from queue or if queue empty, from chain
   * @return last block hash
   */
  blk_hash_t lastPbftBlockHashFromQueueOrChain();

  /**
   * @brief Get PBFT lambda. PBFT lambda is a timer clock
   * @return PBFT lambda
   */
  u_long getPbftInitialLambda() const { return LAMBDA_ms_MIN; }

  /**
   * @brief Calculate DAG blocks ordering hash
   * @param dag_block_hashes DAG blocks hashes
   * @return DAG blocks ordering hash
   */
  static blk_hash_t calculateOrderHash(const std::vector<blk_hash_t> &dag_block_hashes);

  /**
   * @brief Calculate DAG blocks ordering hash
   * @param dag_blocks DAG blocks
   * @return DAG blocks ordering hash
   */
  static blk_hash_t calculateOrderHash(const std::vector<DagBlock> &dag_blocks);

  /**
   * @brief Reorder transactions data if DAG reordering caused transactions with same sender to have nonce in incorrect
   * order. Reordering is deterministic so that same order is produced on any node on any platform
   * @param transactions transactions to reorder
   */
  static void reorderTransactions(SharedTransactions &transactions);

  /**
   * @brief Check a block weight of gas estimation
   * @param dag_blocks dag blocks
   * @return true if total weight of gas estimation is less or equal to gas limit. Otherwise return false
   */
  bool checkBlockWeight(const std::vector<DagBlock> &dag_blocks) const;

  blk_hash_t getLastPbftBlockHash();

  /**
   * @brief Validates vote
   *
   * @param vote to be validated
   * @return <true, ""> vote validation passed, otherwise <false, "err msg">
   */
  std::pair<bool, std::string> validateVote(const std::shared_ptr<Vote> &vote) const;

  /**
   * @brief Push proposed block into the proposed_blocks_ in case it is not there yet
   *
   * @param proposed_block
   * @param propose_vote
   */
  void processProposedBlock(const std::shared_ptr<PbftBlock> &proposed_block,
                            const std::shared_ptr<Vote> &propose_vote);

  // **** Notice: functions used only in tests ****
  // TODO: Add a check for some kind of guards to ensure these are only called from within a test
  /**
   * @brief Resume PBFT daemon. Only to be used for unit tests
   */
  void resume();

  /**
   * @brief Resume PBFT daemon on single state. Only to be used for unit tests
   */
  void resumeSingleState();

  /**
   * @return ProposedBlocks structure
   */
  const ProposedBlocks &getProposedBlocksSt() const;

  /**
   * @brief Get PBFT committee size
   * @return PBFT committee size
   */
  size_t getPbftCommitteeSize() const { return COMMITTEE_SIZE; }

  /**
   * @brief Get 2t+1. 2t+1 is 2/3 of PBFT sortition threshold and plus 1 for a specific period
   * @param pbft_period pbft period
   * @return PBFT 2T + 1 if successful, otherwise (due to non-existent data for pbft_period) empty optional
   */
  std::optional<uint64_t> getPbftTwoTPlusOne(uint64_t pbft_period) const;

 private:
  // DPOS
  /**
   * @brief wait for DPOS period finalization
   */
  void waitForPeriodFinalization();

  /**
   * @brief Reset PBFT step to 1
   */
  void resetStep();

  /**
   * @brief If node receives 2t+1 next votes for some block(including NULL_BLOCK_HASH), advance round to + 1.
   * @return true if PBFT round advanced, otherwise false
   */
  bool advanceRound();

  /**
   * @brief If node receives 2t+1 cert votes for some valid block and pushes it to the chain, advance period to + 1.
   * @return true if PBFT period advanced, otherwise false
   */
  bool advancePeriod();

  /**
   * @brief Check if there is 2t+1 cert votes for some valid block, if yes - push it into the chain
   * @return true if new cert voted block was pushed into the chain, otheriwse false
   */
  bool tryPushCertVotesBlock();

  /**
   * @brief Resets pbft consensus: current pbft round is set to round, step is set to the beginning value
   * @param round
   */
  void resetPbftConsensus(uint64_t round);

  /**
   * @brief Time to sleep for PBFT protocol
   */
  void sleep_();

  /**
   * @brief PBFT daemon
   */
  void continuousOperation_();

  /**
   * @brief Go to next PBFT state. Only to be used for unit tests
   */
  void doNextState_();

  /**
   * @brief Set next PBFT state
   */
  void setNextState_();

  /**
   * @brief Set PBFT filter state
   */
  void setFilterState_();

  /**
   * @brief Set PBFT certify state
   */
  void setCertifyState_();

  /**
   * @brief Set PBFT finish state
   */
  void setFinishState_();

  /**
   * @brief Set PBFT finish polling state
   */
  void setFinishPollingState_();

  /**
   * @brief Set back to PBFT finish state from PBFT finish polling state
   */
  void loopBackFinishState_();

  /**
   * @brief If there are any synced PBFT blocks from peers, push the synced blocks in PBFT chain. Verify all received
   * incoming votes. If there are enough certify votes, push voting PBFT block in PBFT chain
   * @return true if there are enough certify votes voting on a new PBFT block, or PBFT goes to a forward round
   */
  bool stateOperations_();

  /**
   * @brief PBFT proposal state. PBFT step 1. Propose a PBFT block and place a proposal vote on the block hash.
   */
  void proposeBlock_();

  /**
   * @brief PBFT filter state. PBFT step 2. Identify a leader block from all received proposed blocks for the current
   * period, and place a soft vote at the leader block hash.
   */
  void identifyBlock_();

  /**
   * @brief PBFT certify state. PBFT step 3. If receive enough soft votes and pass verification, place a cert vote at
   * the value.
   */
  void certifyBlock_();

  /**
   * @brief PBFT finish state. Happens at even number steps from step 4. Place a next vote at finishing value for the
   * current PBFT round.
   */
  void firstFinish_();

  /**
   * @brief PBFT finish polling state: Happens at odd number steps from step 5. Place a next vote at finishing value for
   * the current PBFT round.
   */
  void secondFinish_();

  /**
   * @brief Place a vote, save it in the verified votes queue, and gossip to peers
   * @param blockhash vote on PBFT block hash
   * @param vote_type vote type
   * @param period PBFT period
   * @param round PBFT round
   * @param step PBFT step
   * @param step PBFT step
   */
  std::shared_ptr<Vote> generateVoteWithWeight(blk_hash_t const &blockhash, PbftVoteTypes vote_type, uint64_t period,
                                               uint64_t round, size_t step);

  /**
   * @brief Place (gossip) vote
   * @param vote
   * @param log_vote_id vote identifier for log msg
   * @param voted_block voted block object - should be == vote->voted_block. In case we dont have block object, nullptr
   *                    is provided
   */
  bool placeVote(const std::shared_ptr<Vote> &, std::string_view log_vote_id,
                 const std::shared_ptr<PbftBlock> &voted_block);

  /**
   * @brief Generate propose vote for provided block place (gossip) it
   *
   * @param proposed_block
   * @return true if successful, otherwise false
   */
  bool genAndPlaceProposeVote(const std::shared_ptr<PbftBlock> &proposed_block);

  /**
   * @brief Gossips newly generated vote to the other peers
   *
   * @param vote
   * @param voted_block
   * @return true if successful, otherwise false
   */
  void gossipNewVote(const std::shared_ptr<Vote> &vote, const std::shared_ptr<PbftBlock> &voted_block);

  /**
   * @brief Propose a new PBFT block
   * @return proposed PBFT block
   */
  std::shared_ptr<PbftBlock> proposePbftBlock_();

  /**
   * @brief Identify a leader block from all received proposed PBFT blocks for the current round by using minimum
   * Verifiable Random Function (VRF) output. In filter state, don’t need check vote value correction.
   * @param round current pbft round
   * @param period new pbft period (perriod == chain_size + 1)
   * @return shared_ptr to leader identified leader block
   */
  std::shared_ptr<PbftBlock> identifyLeaderBlock_(uint64_t round, uint64_t period);

  /**
   * @brief Calculate the lowest hash of a vote by vote weight
   * @param vote vote
   * @return lowest hash of a vote
   */
  h256 getProposal(const std::shared_ptr<Vote> &vote) const;

  /**
   * @brief Check that there are all DAG blocks with correct ordering, total gas estimation is not greater than gas
   * limit, and PBFT block includes all reward votes.
   * @param pbft_block PBFT block
   * @return true if pass verification
   */
  bool compareBlocksAndRewardVotes_(const std::shared_ptr<PbftBlock> &pbft_block);

  /**
   * @brief If there are enough certify votes, push the vote PBFT block in PBFT chain
   * @param pbft_block PBFT block
   * @param current_round_cert_votes certify votes
   * @return true if push a new PBFT block in chain
   */
  bool pushCertVotedPbftBlockIntoChain_(const std::shared_ptr<PbftBlock> &pbft_block,
                                        std::vector<std::shared_ptr<Vote>> &&current_round_cert_votes);

  /**
   * @brief Final chain executes a finalized PBFT block
   * @param period_data PBFT block, cert votes, DAG blocks, and transactions
   * @param finalized_dag_blk_hashes DAG blocks hashes
   * @param synchronous_processing wait for block finalization to finish
   */
  void finalize_(PeriodData &&period_data, std::vector<h256> &&finalized_dag_blk_hashes,
                 bool synchronous_processing = false);

  /**
   * @brief Push a new PBFT block into the PBFT chain
   * @param period_data PBFT block, cert votes for previous period, DAG blocks, and transactions
   * @param cert_votes cert votes for pbft block period
   * @return true if push a new PBFT block into the PBFT chain
   */
  bool pushPbftBlock_(PeriodData &&period_data, std::vector<std::shared_ptr<Vote>> &&cert_votes);

  /**
   * @brief Check if previous round next voting value has been changed
   */
  void checkPreviousRoundNextVotedValueChange_();

  /**
   * @param period
   * @param round
   * @return Soft voted block data if there is enough (2t+1) soft votes, otherwise returns empty optional
   */
  const std::optional<TwoTPlusOneSoftVotedBlockData> &getTwoTPlusOneSoftVotedBlockData(uint64_t period, uint64_t round);

  /**
   * @brief Process synced PBFT blocks if PBFT syncing queue is not empty
   * @return period data with cert votes for the current period
   */
  std::optional<std::pair<PeriodData, std::vector<std::shared_ptr<Vote>>>> processPeriodData();

  /**
   * @brief Validates PBFT block cert votes
   * @param pbft_block
   * @param cert_votes
   *
   * @return true if there is enough(2t+1) votes and all of them are valid, otherwise false
   */
  bool validatePbftBlockCertVotes(const std::shared_ptr<PbftBlock> pbft_block,
                                  const std::vector<std::shared_ptr<Vote>> &cert_votes) const;

  /**
   * @param period
   * @return true if node can participate in consensus - is dpos eligible to vote and create blocks for specified period
   */
  bool canParticipateInConsensus(uint64_t period) const;

  /**
   * @brief Get PBFT sortition threshold for specific period
   * @param total_dpos_votes_count total votes count
   * @param vote_type vote type
   * @return PBFT sortition threshold
   */
  uint64_t getPbftSortitionThreshold(uint64_t total_dpos_votes_count, PbftVoteTypes vote_type) const;

  /**
   * @brief Broadcast or rebroadcast current round soft votes, previous round next votes and reward votes
   * @param rebroadcast
   */
  void broadcastVotes(bool rebroadcast);

  std::atomic<bool> stopped_ = true;

  // Multiple proposed pbft blocks could have same dag block anchor at same period so this cache improves retrieval of
  // dag block order for specific anchor
  std::unordered_map<blk_hash_t, std::vector<DagBlock>> anchor_dag_block_order_cache_;

  // Ensures that only one PBFT block per period can be proposed
  std::shared_ptr<PbftBlock> proposed_block_ = nullptr;

  std::unique_ptr<std::thread> daemon_;
  std::shared_ptr<DbStorage> db_;
  std::shared_ptr<NextVotesManager> next_votes_manager_;
  std::shared_ptr<PbftChain> pbft_chain_;
  std::shared_ptr<VoteManager> vote_mgr_;
  std::shared_ptr<DagManager> dag_mgr_;
  std::weak_ptr<Network> network_;
  std::shared_ptr<TransactionManager> trx_mgr_;
  std::shared_ptr<FinalChain> final_chain_;
  std::shared_ptr<KeyManager> key_manager_;

  const addr_t node_addr_;
  const secret_t node_sk_;
  const dev::Public node_pub_;
  const vrf_sk_t vrf_sk_;

  u_long const LAMBDA_ms_MIN;
  u_long LAMBDA_ms = 0;
  u_long LAMBDA_backoff_multiple = 1;
  const u_long kMaxLambda = 60000;  // in ms, max lambda is 1 minutes

  const uint32_t kBroadcastVotesLambdaTime = 20;
  const uint32_t kRebroadcastVotesLambdaTime = 60;
  uint32_t broadcast_votes_counter_ = 1;
  uint32_t rebroadcast_votes_counter_ = 1;

  std::default_random_engine random_engine_{std::random_device{}()};

  // Flag that says if node is in sync after it enters new round
  // bool new_round_in_sync_ = false;

  const size_t COMMITTEE_SIZE;
  const size_t NUMBER_OF_PROPOSERS;
  const size_t DAG_BLOCKS_SIZE;
  const size_t GHOST_PATH_MOVE_BACK;

  PbftStates state_ = value_proposal_state;

  std::atomic<uint64_t> round_ = 1;
  size_t step_ = 1;
  size_t startingStepInRound_ = 1;

  // 2t+1 soft voted block related data
  std::optional<TwoTPlusOneSoftVotedBlockData> soft_voted_block_for_round_{};

  // Block that node cert voted
  std::optional<std::shared_ptr<PbftBlock>> cert_voted_block_for_round_{};

  std::optional<blk_hash_t> previous_round_next_voted_value_{};
  bool previous_round_next_voted_null_block_hash_ = false;

  time_point round_clock_initial_datetime_;
  time_point now_;

  std::chrono::duration<double> duration_;
  u_long next_step_time_ms_ = 0;
  u_long elapsed_time_in_round_ms_ = 0;

  bool executed_pbft_block_ = false;
  bool next_voted_soft_value_ = false;
  bool next_voted_null_block_hash_ = false;
  bool go_finish_state_ = false;
  bool loop_back_finish_state_ = false;

  // Cache for current 2T+1 - do not access it directly as it is not updated automatically,
  // always call getPbftTwoTPlusOne instead !!!
  mutable std::pair<uint64_t /* period */, uint64_t /* two_t_plus_one for period */> current_two_t_plus_one_;
  mutable std::shared_mutex current_two_t_plus_one_mutex_;

  const blk_hash_t dag_genesis_block_hash_;

  const PbftConfig &config_;

  std::condition_variable stop_cv_;
  std::mutex stop_mtx_;

  PeriodDataQueue sync_queue_;

  // Proposed blocks based on received propose votes
  ProposedBlocks proposed_blocks_;

  const uint32_t max_levels_per_period_;

  size_t last_step_ = 0;
  time_point last_step_clock_initial_datetime_;
  time_point current_step_clock_initial_datetime_;
  // END TEST CODE

  LOG_OBJECTS_DEFINE
};

/** @}*/

}  // namespace taraxa
