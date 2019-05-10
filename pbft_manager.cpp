/*
 * @Copyright: Taraxa.io
 * @Author: Qi Gao
 * @Date: 2019-04-10
 * @Last Modified by: Qi Gao
 * @Last Modified time: 2019-04-23
 */

#include "pbft_manager.hpp"

#include "dag.hpp"
#include "full_node.hpp"
#include "libdevcore/SHA3.h"
#include "network.hpp"
#include "sortition.h"
#include "util.hpp"

#include <chrono>
#include <string>

namespace taraxa {

PbftManager::PbftManager() {}
PbftManager::PbftManager(const PbftManagerConfig &config)
  : LAMBDA_ms(1000) {} //LAMBDA_ms(config.lambda_ms) {}

void PbftManager::setFullNode(shared_ptr<taraxa::FullNode> node) {
  node_ = node;
  auto full_node = node_.lock();
  if (!full_node) {
    LOG(log_err_) << "Full node unavailable" << std::endl;
    return;
  }
  vote_queue_ = full_node->getVoteQueue();
  pbft_chain_ = full_node->getPbftChain();
}

void PbftManager::start() {
  if (!stopped_) {
    return;
  }
  stopped_ = false;
  executor_ = std::make_shared<std::thread>([this]() { run(); });
  LOG(log_inf_) << "A PBFT executor initiated ..." << std::endl;
}

void PbftManager::stop() {
  if (stopped_) {
    return;
  }
  stopped_ = true;
  executor_->join();
  executor_.reset();
  LOG(log_inf_) << "A PBFT executor terminated ..." << std::endl;
  assert(executor_ == nullptr);
}

/* When a node starts up it has to sync to the current phase (type of block
 * being generated) and step (within the block generation period)
 * Five step loop for block generation over three phases of blocks
 * User's credential, sigma_i_p for a period p is sig_i(R, p)
 * Leader l_i_p = min ( H(sig_j(R,p) ) over set of j in S_i where S_i is set of
 * users from which have received valid period p credentials
 */
void PbftManager::run() {
  auto period_clock_initial_datetime = std::chrono::system_clock::now();
  std::unordered_map<size_t, blk_hash_t> cert_voted_values_for_period;

  while (!stopped_) {
    auto now = std::chrono::system_clock::now();
    auto duration = now - period_clock_initial_datetime;
    auto elapsed_time_in_round_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    auto next_step_time_ms = 0;

    LOG(log_deb_) << "PBFT period is " << pbft_period_;
    LOG(log_deb_) << "PBFT step is " << pbft_step_;

    // Get votes
    std::vector<Vote> votes = vote_queue_->getVotes(pbft_period_ - 1);

    blk_hash_t nodes_own_starting_value_for_period = NULL_BLOCK_HASH;

    // Check if we are synced to the right step ...
    size_t consensus_pbft_period =
        periodDeterminedFromVotes_(votes, pbft_period_);

    if (consensus_pbft_period != pbft_period_) {
      LOG(log_deb_) << "Period determined from votes: "
                    << consensus_pbft_period;
      pbft_period_ = consensus_pbft_period;
      LOG(log_deb_) << "Advancing clock to pbft period " << pbft_period_
                    << ", step 1, and resetting clock.";
      // NOTE: This also sets pbft_step back to 1
      pbft_step_ = 1;
      period_clock_initial_datetime = std::chrono::system_clock::now();
      continue;
    }

    if (pbft_step_ == 1) {
      // Value Proposal
      if (pbft_period_ == 1 ||
          (pbft_period_ >= 2 &&
           nullBlockNextVotedForPeriod_(votes, pbft_period_ - 1))) {
        // Propose value...
        LOG(log_deb_) << "Propose my value...";
        std::pair<blk_hash_t, bool> proposed_block_hash = proposeMyPbftBlock_();
        if (proposed_block_hash.second) {
          placeVoteIfCanSpeak_(proposed_block_hash.first, propose_vote_type,
              pbft_period_, pbft_step_, false);
        }
      } else if (pbft_period_ >= 2) {
        std::pair<blk_hash_t, bool> next_voted_block_from_previous_period =
            nextVotedBlockForPeriod_(votes, pbft_period_ - 1);
        if (next_voted_block_from_previous_period.second) {
          LOG(log_deb_) << "Proposing next voted block "
                        << next_voted_block_from_previous_period.first
                        << " from previous period.";
          placeVoteIfCanSpeak_(next_voted_block_from_previous_period.first,
              propose_vote_type, pbft_period_, pbft_step_, false);
        }
      }
      next_step_time_ms = 2 * LAMBDA_ms;
      LOG(log_deb_) << "next step time(ms): " << next_step_time_ms;
      pbft_step_ += 1;

    } else if (pbft_step_ == 2) {
      // The Filtering Step
      if (pbft_period_ == 1 ||
          (pbft_period_ >= 2 &&
           nullBlockNextVotedForPeriod_(votes, pbft_period_ - 1))) {
        // Identity leader
        LOG(log_tra_) << "Identify leader l_i_p for period p and soft vote the"
                        " value that they proposed...";
        std::pair<blk_hash_t, bool> leader_block = identifyLeaderBlock_();
        if (leader_block.second) {
          placeVoteIfCanSpeak_(leader_block.first, soft_vote_type, pbft_period_,
                               pbft_step_, false);
        }
      } else if (pbft_period_ >= 2) {
        std::pair<blk_hash_t, bool> next_voted_block_from_previous_period =
            nextVotedBlockForPeriod_(votes, pbft_period_ - 1);
        if (next_voted_block_from_previous_period.second) {
          LOG(log_tra_) << "Soft voting "
                        << next_voted_block_from_previous_period.first
                        << " from previous period";
          placeVoteIfCanSpeak_(next_voted_block_from_previous_period.first,
                               soft_vote_type, pbft_period_, pbft_step_, false);
        }
      }

      next_step_time_ms = 2 * LAMBDA_ms;
      LOG(log_deb_) << "next step time(ms): " << next_step_time_ms;
      pbft_step_ = pbft_step_ + 1;

    } else if (pbft_step_ == 3) {
      // The Certifying Step
      if (elapsed_time_in_round_ms > 2 * LAMBDA_ms) {
        LOG(log_deb_) << "PBFT Reached step 3 too quickly?";
      }

      bool should_go_to_step_four = false;

      if (elapsed_time_in_round_ms > 4 * LAMBDA_ms - POLLING_INTERVAL_ms) {
        LOG(log_deb_) << "will go to step 4";
        should_go_to_step_four = true;
      } else {
        std::pair<blk_hash_t, bool> soft_voted_block_for_this_period =
            softVotedBlockForPeriod_(votes, pbft_period_);
        if (soft_voted_block_for_this_period.second) {
          should_go_to_step_four = true;
          LOG(log_deb_) << "Cert voting "
                        << soft_voted_block_for_this_period.first
                        << " for this period";
          cert_voted_values_for_period[pbft_period_] =
              soft_voted_block_for_this_period.first;
          placeVoteIfCanSpeak_(soft_voted_block_for_this_period.first,
                               cert_vote_type, pbft_period_, pbft_step_, false);
        }
      }

      if (should_go_to_step_four) {
        LOG(log_deb_) << "will go to step 4";
        next_step_time_ms = 4 * LAMBDA_ms;
        pbft_step_ += 1;
      } else {
        next_step_time_ms = next_step_time_ms + POLLING_INTERVAL_ms;
      }
      LOG(log_deb_) << "next step time(ms): " << next_step_time_ms;

    } else if (pbft_step_ == 4) {
      if (cert_voted_values_for_period.find(pbft_period_) !=
          cert_voted_values_for_period.end()) {
        LOG(log_deb_) << "Next voting value "
                      << cert_voted_values_for_period[pbft_period_]
                      << " for period " << pbft_period_;
        placeVoteIfCanSpeak_(cert_voted_values_for_period[pbft_period_],
                             next_vote_type, pbft_period_, pbft_step_, false);
      } else if (pbft_period_ >= 2 &&
                 nullBlockNextVotedForPeriod_(votes, pbft_period_ - 1)) {
        LOG(log_deb_) << "Next voting NULL BLOCK for period " << pbft_period_;
        placeVoteIfCanSpeak_(NULL_BLOCK_HASH, next_vote_type, pbft_period_,
                             pbft_step_, false);
      } else {
        LOG(log_deb_) << "Next voting nodes own starting value for period "
                      << pbft_period_;
        placeVoteIfCanSpeak_(nodes_own_starting_value_for_period,
                             next_vote_type, pbft_period_, pbft_step_, false);
      }

      pbft_step_ += 1;
      next_step_time_ms = 4 * LAMBDA_ms;
      LOG(log_deb_) << "next step time(ms): " << next_step_time_ms;

    } else if (pbft_step_ == 5) {
      std::pair<blk_hash_t, bool> soft_voted_block_for_this_period =
          softVotedBlockForPeriod_(votes, pbft_period_);
      bool have_next_voted = false;

      if (soft_voted_block_for_this_period.second) {
        LOG(log_tra_) << "Next voting "
                      << soft_voted_block_for_this_period.first
                      << " for this period";
        have_next_voted = true;
        placeVoteIfCanSpeak_(soft_voted_block_for_this_period.first,
                             next_vote_type, pbft_period_, pbft_step_, false);
      } else if (pbft_period_ >= 2 &&
                 nullBlockNextVotedForPeriod_(votes, pbft_period_ - 1) &&
                 (cert_voted_values_for_period.find(pbft_period_) ==
                  cert_voted_values_for_period.end())) {
        LOG(log_tra_) << "Next voting NULL BLOCK for this period";
        have_next_voted = true;
        placeVoteIfCanSpeak_(NULL_BLOCK_HASH, next_vote_type, pbft_period_,
                             pbft_step_, false);
      }

      if (have_next_voted) {
        pbft_period_ += 1;
        LOG(log_tra_) << "Having next voted, advancing clock to pbft period "
                      << pbft_period_ << ", step 1, and resetting clock.";
        // NOTE: This also sets pbft_step back to 1
        pbft_step_ = 1;
        period_clock_initial_datetime = std::chrono::system_clock::now();
        continue;
      } else if (elapsed_time_in_round_ms >
                 6 * LAMBDA_ms - POLLING_INTERVAL_ms) {
        next_step_time_ms = 6 * LAMBDA_ms;
        pbft_step_ += 1;
      } else {
        next_step_time_ms += POLLING_INTERVAL_ms;
      }
      LOG(log_deb_) << "next step time(ms): " << next_step_time_ms;

    } else if (pbft_step_ % 2 == 0) {
      // Even number steps 6, 8, 10... < MAX_STEPS are a repeat of step 4...
      if (cert_voted_values_for_period.find(pbft_period_) !=
          cert_voted_values_for_period.end()) {
        LOG(log_tra_) << "Next voting value "
                      << cert_voted_values_for_period[pbft_period_]
                      << " for period " << pbft_period_;
        placeVoteIfCanSpeak_(cert_voted_values_for_period[pbft_period_],
                             next_vote_type, pbft_period_, pbft_step_, false);
      } else if (pbft_period_ >= 2 &&
                 nullBlockNextVotedForPeriod_(votes, pbft_period_ - 1)) {
        LOG(log_tra_) << "Next voting NULL BLOCK for period " << pbft_period_;
        placeVoteIfCanSpeak_(NULL_BLOCK_HASH, next_vote_type, pbft_period_,
                             pbft_step_, false);
      } else {
        LOG(log_tra_) << "Next voting nodes own starting value for period "
                      << pbft_period_;
        placeVoteIfCanSpeak_(nodes_own_starting_value_for_period,
                             next_vote_type, pbft_period_, pbft_step_, false);
      }

      pbft_step_ += 1;

    } else {
      // Odd number steps 7, 9, 11... < MAX_STEPS are a repeat of step 5...
      std::pair<blk_hash_t, bool> soft_voted_block_for_this_period =
          softVotedBlockForPeriod_(votes, pbft_period_);
      bool have_next_voted = false;

      if (soft_voted_block_for_this_period.second) {
        LOG(log_tra_) << "Next voting "
                      << soft_voted_block_for_this_period.first
                      << " for this period";
        have_next_voted = true;
        placeVoteIfCanSpeak_(soft_voted_block_for_this_period.first,
                             next_vote_type, pbft_period_, pbft_step_, false);
      } else if (pbft_period_ >= 2 &&
                 nullBlockNextVotedForPeriod_(votes, pbft_period_ - 1) &&
                 (cert_voted_values_for_period.find(pbft_period_) ==
                  cert_voted_values_for_period.end())) {
        LOG(log_tra_) << "Next voting NULL BLOCK for this period";
        have_next_voted = true;
        placeVoteIfCanSpeak_(NULL_BLOCK_HASH, next_vote_type, pbft_period_,
                             pbft_step_, false);
      }

      if (have_next_voted || pbft_step_ >= MAX_STEPS) {
        pbft_period_ += 1;
        LOG(log_tra_) << "Having next voted, advancing clock to pbft period "
                      << pbft_period_ << ", step 1, and resetting clock.";
        // NOTE: This also sets pbft_step back to 1
        pbft_step_ = 1;
        period_clock_initial_datetime = std::chrono::system_clock::now();
        continue;
      } else if (elapsed_time_in_round_ms >
                 (pbft_step_ + 1) * LAMBDA_ms - POLLING_INTERVAL_ms) {
        next_step_time_ms = (pbft_step_ + 1) * LAMBDA_ms;
        pbft_step_ += 1;
      } else {
        next_step_time_ms += POLLING_INTERVAL_ms;
      }
      LOG(log_deb_) << "next step time(ms): " << next_step_time_ms;
    }

    now = std::chrono::system_clock::now();
    duration = now - period_clock_initial_datetime;
    elapsed_time_in_round_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    auto time_to_sleep_for_ms = next_step_time_ms - elapsed_time_in_round_ms;
    LOG(log_deb_) << "Time to sleep(ms): " << time_to_sleep_for_ms;
    if (time_to_sleep_for_ms > 0) {
      thisThreadSleepForMilliSeconds(time_to_sleep_for_ms);
    }
  }
}

bool PbftManager::shouldSpeak(blk_hash_t const &blockhash, char type,
                              uint64_t period, size_t step) {
  std::string message = blockhash.toString() + std::to_string(type) +
                        std::to_string(period) + std::to_string(step);
  auto full_node = node_.lock();
  if (!full_node) {
    LOG(log_err_) << "Full node unavailable" << std::endl;
    return false;
  }
  dev::Signature signature = full_node->signMessage(message);
  string signature_hash = taraxa::hashSignature(signature);
  std::pair<bal_t, bool> account_balance =
      full_node->getBalance(full_node->getAddress());
  if (!account_balance.second) {
    LOG(log_tra_) << "Full node account unavailable" << std::endl;
    return false;
  }
  if (taraxa::sortition(signature_hash, account_balance.first)) {
    LOG(log_inf_) << "Win sortition" << std::endl;
    return true;
  } else {
    return false;
  }
}

/* Find the latest period, p-1, for which there is a quorum of next-votes
 * and set determine that period p should be the current period...
 */
size_t PbftManager::periodDeterminedFromVotes_(std::vector<Vote> &votes,
                                               uint64_t local_period) {
  // tally next votes by period
  // store in reverse order
  std::map<size_t, size_t, std::greater<size_t> > next_votes_tally_by_period;

  for (Vote &v : votes) {
    if (v.getType() != next_vote_type) {
      continue;
    }

    size_t vote_period = v.getPeriod();
    if (vote_period >= local_period) {
      if (next_votes_tally_by_period.find(vote_period) !=
          next_votes_tally_by_period.end()) {
        next_votes_tally_by_period[vote_period] += 1;
      } else {
        next_votes_tally_by_period[vote_period] = 1;
      }
    }
  }

  for (auto &vp : next_votes_tally_by_period) {
    if (vp.second >= TWO_T_PLUS_ONE) {
      std::vector<Vote> next_vote_for_period =
          getVotesOfTypeFromPeriod_(next_vote_type, votes, vp.first,
                                    std::make_pair(blk_hash_t(0), false));
      if (blockWithEnoughVotes_(next_vote_for_period).second) {
        return vp.first + 1;
      }
    }
  }

  return local_period;
}

std::vector<Vote> PbftManager::getVotesOfTypeFromPeriod_(
    PbftVoteTypes vote_type, std::vector<Vote> &votes, uint64_t period,
    std::pair<blk_hash_t, bool> blockhash) {
  // We should read through the votes ...
  std::vector<Vote> votes_of_requested_type;

  for (Vote &v : votes) {
    if (v.getType() == vote_type && v.getPeriod() == period &&
        (blockhash.second == false || blockhash.first == v.getBlockHash())) {
      votes_of_requested_type.emplace_back(v);
    }
  }

  return votes_of_requested_type;
}

// Assumption is that all votes are in the same period and of same type...
std::pair<blk_hash_t, bool> PbftManager::blockWithEnoughVotes_(
    std::vector<Vote> &votes) {
  bool is_first_block = true;
  PbftVoteTypes vote_type;
  uint64_t vote_period;
  blk_hash_t blockhash;
  // store in reverse order
  std::map<blk_hash_t, size_t, std::greater<blk_hash_t> > tally_by_blockhash;

  for (Vote &v : votes) {
    if (is_first_block) {
      vote_type = static_cast<PbftVoteTypes>(v.getType()); //TODO: need change vote type to PbftVoteTypes
      vote_period = v.getPeriod();
      is_first_block = false;
    } else {
      bool vote_type_and_period_is_consistent =
          (vote_type == v.getType() && vote_period == v.getPeriod());
      if (!vote_type_and_period_is_consistent) {
        LOG(log_err_) << "Vote types and periods were not internally"
                         " consistent!";
        assert(false);
      }
    }

    blockhash = v.getBlockHash();
    if (tally_by_blockhash.find(blockhash) != tally_by_blockhash.end()) {
      tally_by_blockhash[blockhash] += 1;
    } else {
      tally_by_blockhash[blockhash] = 1;
    }

    for (auto &blockhash_pair : tally_by_blockhash) {
      if (blockhash_pair.second >= TWO_T_PLUS_ONE) {
        return std::make_pair(blockhash_pair.first, true);
      }
    }
  }

  return std::make_pair(blk_hash_t(0), false);
}

bool PbftManager::nullBlockNextVotedForPeriod_(std::vector<Vote> &votes,
                                               uint64_t period) {
  blk_hash_t blockhash = NULL_BLOCK_HASH;
  std::pair<blk_hash_t, bool> blockhash_pair = std::make_pair(blockhash, true);
  std::vector<Vote> votes_for_null_block_in_period =
      getVotesOfTypeFromVotesForPeriod_(next_vote_type, votes, period,
                                        blockhash_pair);
  if (votes_for_null_block_in_period.size() >= TWO_T_PLUS_ONE) {
    return true;
  }
  return false;
}

std::vector<Vote> PbftManager::getVotesOfTypeFromVotesForPeriod_(
    PbftVoteTypes vote_type, std::vector<Vote> &votes, uint64_t period,
    std::pair<blk_hash_t, bool> blockhash) {
  std::vector<Vote> votes_of_requested_type;

  for (Vote &v : votes) {
    if (v.getType() == vote_type && v.getPeriod() == period &&
        (blockhash.second == false || blockhash.first == v.getBlockHash())) {
      votes_of_requested_type.emplace_back(v);
    }
  }

  return votes_of_requested_type;
}

std::pair<blk_hash_t, bool> PbftManager::nextVotedBlockForPeriod_(
    std::vector<Vote> &votes, uint64_t period) {
  std::vector<Vote> next_votes_for_period = getVotesOfTypeFromVotesForPeriod_(
      next_vote_type, votes, period, std::make_pair(blk_hash_t(0), false));

  return blockWithEnoughVotes_(next_votes_for_period);
}

void PbftManager::placeVoteIfCanSpeak_(taraxa::blk_hash_t blockhash,
                                       PbftVoteTypes vote_type,
                                       uint64_t period,
                                       size_t step,
                                       bool override_sortition_check) {
  bool should_i_speak_response = true;

  if (!override_sortition_check) {
    should_i_speak_response = shouldSpeak(blockhash, vote_type, period, step);
  }
  if (should_i_speak_response) {
    auto full_node = node_.lock();
    if (!full_node) {
      LOG(log_err_) << "Full node unavailable" << std::endl;
      return;
    }
    full_node->placeVote(blockhash, vote_type, period, step);
    // pbft vote broadcast
    broadcastPbftVote_(blockhash, vote_type, period, step);
  }
}

void PbftManager::broadcastPbftVote_(taraxa::blk_hash_t &blockhash,
                                    taraxa::PbftVoteTypes vote_type,
                                    uint64_t period, size_t step) {
  auto full_node = node_.lock();
  if (!full_node) {
    LOG(log_err_) << "Full node unavailable" << std::endl;
    return;
  }

  std::string message = blockhash.toString() +
                        std::to_string(vote_type) +
                        std::to_string(period) +
                        std::to_string(step);
  sig_t signature = full_node->signMessage(message);
  public_t public_key = full_node->getPublicKey();
  Vote vote(public_key, signature, blockhash, vote_type, period, step);

  std::shared_ptr<Network> network = full_node->getNetwork();
  network->onNewPbftVote(vote);
}

std::pair<blk_hash_t, bool> PbftManager::softVotedBlockForPeriod_(
    std::vector<taraxa::Vote> &votes, uint64_t period) {
  std::vector<Vote> soft_votes_for_period = getVotesOfTypeFromVotesForPeriod_(
      soft_vote_type, votes, period, std::make_pair(blk_hash_t(0), false));

  return blockWithEnoughVotes_(soft_votes_for_period);
}

std::pair<blk_hash_t, bool> PbftManager::proposeMyPbftBlock_() {
  auto full_node = node_.lock();
  if (!full_node) {
    LOG(log_err_) << "Full node unavailable" << std::endl;
    return std::make_pair(blk_hash_t(0), false);
  }
  PbftBlock pbft_block;
  PbftBlockTypes current_block_type = pbft_chain_->getNextPbftBlockType();
  if (current_block_type == pivot_block_type) {
    blk_hash_t prev_pivot_hash = pbft_chain_->getLastPbftPivotHash();
    blk_hash_t prev_block_hash = pbft_chain_->getLastPbftBlockHash();
    // define pivot block in DAG
    std::vector<std::string> ghost;
    full_node->getGhostPath(Dag::GENESIS, ghost);
    blk_hash_t dag_block_hash(ghost.back());

    uint64_t epoch = full_node->getEpoch();
    uint64_t timestamp = std::time(nullptr);
    addr_t beneficiary = full_node->getAddress();
    // generate pivot block
    PivotBlock pivot_block(prev_pivot_hash, prev_block_hash, dag_block_hash,
        epoch, timestamp, beneficiary);
    // set pbft block as pivot
    pbft_block.setPivotBlock(pivot_block);
    pbft_block.setBlockHash();
  } else if (current_block_type == schedule_block_type) {
    blk_hash_t prev_block_hash = pbft_chain_->getLastPbftBlockHash();
    uint64_t timestamp = std::time(nullptr);
    // get dag block hash from the last pbft block(pivot) in pbft chain
    blk_hash_t last_block_hash = pbft_chain_->getLastPbftBlockHash();
    std::pair<PbftBlock, bool> last_pbft_block =
        pbft_chain_->getPbftBlock(last_block_hash);
    if (!last_pbft_block.second) {
      LOG(log_err_) << "Cannot find last pbft block with block hash: "
                    << last_block_hash;
      return std::make_pair(blk_hash_t(0), false);
    }
    blk_hash_t dag_block_hash =
        last_pbft_block.first.getPivotBlock().getDagBlockHash();
    // get dag blocks order
    uint64_t epoch;
    std::shared_ptr<vec_blk_t> dag_blocks_order;
    std::tie(epoch, dag_blocks_order) =
        full_node->createPeriodAndComputeBlockOrder(dag_block_hash);
    // generate fake transaction schedule
    std::shared_ptr<TrxSchedule> schedule =
        full_node->createMockTrxSchedule(dag_blocks_order);
    // generate pbft schedule block
    ScheduleBlock schedule_block(prev_block_hash, timestamp, *schedule);
    // set pbft block as schedule
    pbft_block.setScheduleBlock(schedule_block);
    pbft_block.setBlockHash();
  } // TODO: More pbft block types

  blk_hash_t pbft_block_hash = pbft_block.getBlockHash();
  // sortition
  if (!shouldSpeak(pbft_block_hash, propose_vote_type, pbft_period_,
                   pbft_step_)) {
    return std::make_pair(blk_hash_t(0), false);
  }
  // sign the pbft block
  std::string message = pbft_block_hash.toString() +
                        std::to_string(propose_vote_type) +
                        std::to_string(pbft_period_) +
                        std::to_string(pbft_step_);
  sig_t signature = full_node->signMessage(message);
  pbft_block.setSignature(signature);
  // push pbft block into pbft queue
  pbft_chain_->pushPbftBlockIntoQueue(pbft_block);
  // broadcast pbft block
  std::shared_ptr<Network> network = full_node->getNetwork();
  network->onNewPbftBlock(pbft_block);

  return std::make_pair(pbft_block_hash, true);
}

std::pair<blk_hash_t, bool> PbftManager::identifyLeaderBlock_() {
  std::vector<Vote> votes = vote_queue_->getVotes(pbft_period_);
  PbftBlockTypes next_pbft_block_type = pbft_chain_->getNextPbftBlockType();
  std::vector<blk_hash_t> leader_candidates;
  for (auto const &v: votes) {
    if (v.getType() == next_pbft_block_type && v.getPeriod() == pbft_period_) {
      leader_candidates.emplace_back(v.getBlockHash());
    }
  }
  if (leader_candidates.empty()) {
    // no eligible leader
    return std::make_pair(blk_hash_t(0), false);
  }
  blk_hash_t leader_block = leader_candidates[0];
  for (auto const &block_hash: leader_candidates) {
    if (block_hash < leader_block) {
      leader_block = block_hash;
    }
  }

  return std::make_pair(leader_block, true);
}

}  // namespace taraxa
