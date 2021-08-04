#include "node_stats.hpp"

#include "consensus/pbft_chain.hpp"
#include "consensus/pbft_manager.hpp"
#include "consensus/vote.hpp"
#include "dag/dag.hpp"
#include "dag/dag_block_manager.hpp"
#include "libp2p/Common.h"
#include "network/tarcap/shared_states/peers_state.hpp"
#include "network/tarcap/shared_states/syncing_state.hpp"
#include "network/tarcap/packets_handlers/common/packets_stats/packets_stats.hpp"
#include "transaction_manager/transaction_manager.hpp"

namespace taraxa::network::tarcap {

NodeStats::NodeStats(std::shared_ptr<PeersState> peers_state, std::shared_ptr<SyncingState> syncing_state,
                     std::shared_ptr<PbftChain> pbft_chain, std::shared_ptr<PbftManager> pbft_mgr,
                     std::shared_ptr<DagManager> dag_mgr, std::shared_ptr<DagBlockManager> dag_blk_mgr,
                     std::shared_ptr<VoteManager> vote_mgr, std::shared_ptr<TransactionManager> trx_mgr,
                     std::shared_ptr<PacketsStats> packets_stats, uint64_t stats_log_interval, const addr_t &node_addr)
    : peers_state_(std::move(peers_state)),
      syncing_state_(std::move(syncing_state)),
      pbft_chain_(std::move(pbft_chain)),
      pbft_mgr_(std::move(pbft_mgr)),
      dag_mgr_(std::move(dag_mgr)),
      dag_blk_mgr_(std::move(dag_blk_mgr)),
      vote_mgr_(std::move(vote_mgr)),
      trx_mgr_(std::move(trx_mgr)),
      packets_stats_(std::move(packets_stats)),
      stats_log_interval_(stats_log_interval) {
  LOG_OBJECTS_CREATE("SUMMARY");
}

uint64_t NodeStats::getNodeStatsLogInterval() const { return stats_log_interval_; }

uint64_t NodeStats::syncTimeSeconds() const { return stats_log_interval_ * syncing_interval_count_ / 1000; }

void NodeStats::logNodeStats() {
  bool is_syncing = syncing_state_->is_syncing();

  dev::p2p::NodeID max_pbft_round_node_id;
  dev::p2p::NodeID max_pbft_chain_node_id;
  dev::p2p::NodeID max_node_dag_level_node_id;
  uint64_t peer_max_pbft_round = 1;
  uint64_t peer_max_pbft_chain_size = 1;
  uint64_t peer_max_node_dag_level = 1;
  const size_t peers_size = peers_state_->getPeersCount();

  for (auto const &peer : peers_state_->getAllPeers()) {
    // Find max pbft chain size
    if (peer.second->pbft_chain_size_ > peer_max_pbft_chain_size) {
      peer_max_pbft_chain_size = peer.second->pbft_chain_size_;
      max_pbft_chain_node_id = peer.first;
    }

    // Find max dag level
    if (peer.second->dag_level_ > peer_max_node_dag_level) {
      peer_max_node_dag_level = peer.second->dag_level_;
      max_node_dag_level_node_id = peer.first;
    }

    // Find max peer PBFT round
    if (peer.second->pbft_round_ > peer_max_pbft_round) {
      peer_max_pbft_round = peer.second->pbft_round_;
      max_pbft_round_node_id = peer.first;
    }
  }

  // Local dag info...
  const auto local_max_level_in_dag = dag_mgr_->getMaxLevel();
  const auto local_max_dag_level_in_queue = dag_blk_mgr_->getMaxDagLevelInQueue();

  // Local pbft info...
  uint64_t local_pbft_round = pbft_mgr_->getPbftRound();
  const auto local_chain_size = pbft_chain_->getPbftChainSize();

  const auto local_dpos_total_votes_count = pbft_mgr_->getDposTotalVotesCount();
  const auto local_weighted_votes = pbft_mgr_->getDposWeightedVotesCount();
  const auto local_twotplusone = pbft_mgr_->getTwoTPlusOne();

  // Syncing period...
  const auto local_pbft_sync_period = pbft_chain_->pbftSyncingPeriod();

  // Decide if making progress...
  const auto pbft_consensus_rounds_advanced = local_pbft_round - local_pbft_round_prev_interval_;
  const auto pbft_chain_size_growth = local_chain_size - local_chain_size_prev_interval_;
  const auto pbft_sync_period_progress = local_pbft_sync_period - local_pbft_sync_period_prev_interval_;
  const auto dag_level_growh = local_max_level_in_dag - local_max_level_in_dag_prev_interval_;

  const bool making_pbft_consensus_progress = (pbft_consensus_rounds_advanced > 0);
  const bool making_pbft_chain_progress = (pbft_chain_size_growth > 0);
  const bool making_pbft_sync_period_progress = (pbft_sync_period_progress > 0);
  const bool making_dag_progress = (dag_level_growh > 0);

  LOG(log_dg_) << "Making PBFT chain progress: " << std::boolalpha << making_pbft_chain_progress << " (advanced "
               << pbft_chain_size_growth << " blocks)";
  if (is_syncing) {
    LOG(log_dg_) << "Making PBFT sync period progress: " << std::boolalpha << making_pbft_sync_period_progress
                 << " (synced " << pbft_sync_period_progress << " blocks)";
  }
  LOG(log_dg_) << "Making PBFT consensus progress: " << std::boolalpha << making_pbft_consensus_progress
               << " (advanced " << pbft_consensus_rounds_advanced << " rounds)";
  LOG(log_dg_) << "Making DAG progress: " << std::boolalpha << making_dag_progress << " (grew " << dag_level_growh
               << " dag levels)";

  // Update syncing interval counts
  syncing_interval_count_ = syncing_state_->is_syncing() ? (syncing_interval_count_ + 1) : 0;
  syncing_stalled_interval_count_ = syncing_state_->is_syncing() && !making_pbft_chain_progress && !making_dag_progress
                                        ? (syncing_stalled_interval_count_ + 1)
                                        : 0;
  if (is_syncing) {
    intervals_syncing_since_launch_++;
  } else {
    intervals_in_sync_since_launch_++;
  }

  LOG(log_nf_) << "Connected to " << peers_size << " peers";

  if (is_syncing) {
    // Syncing...
    const auto percent_synced = (local_pbft_sync_period * 100) / peer_max_pbft_chain_size;
    const auto syncing_time_sec = syncTimeSeconds();
    LOG(log_nf_) << "Syncing for " << syncing_time_sec << " seconds, " << percent_synced << "% synced";
    LOG(log_nf_) << "Currently syncing from node " << syncing_state_->syncing_peer();
    LOG(log_nf_) << "Max peer PBFT chain size:      " << peer_max_pbft_chain_size << " (peer " << max_pbft_chain_node_id
                 << ")";
    LOG(log_nf_) << "Max peer PBFT consensus round:  " << peer_max_pbft_round << " (peer " << max_pbft_round_node_id
                 << ")";
    LOG(log_nf_) << "Max peer DAG level:             " << peer_max_node_dag_level << " (peer "
                 << max_node_dag_level_node_id << ")";
  } else {
    const auto sync_percentage =
        (100 * intervals_in_sync_since_launch_) / (intervals_in_sync_since_launch_ + intervals_syncing_since_launch_);
    LOG(log_nf_) << "In sync since launch for " << sync_percentage << "% of the time";
    LOG(log_nf_) << "Max DAG block level in DAG:    " << local_max_level_in_dag;
    LOG(log_nf_) << "Max DAG block level in queue:  " << local_max_dag_level_in_queue;
    LOG(log_nf_) << "PBFT chain size:               " << local_chain_size;
    LOG(log_nf_) << "Current PBFT round:            " << local_pbft_round;
    LOG(log_nf_) << "DPOS total votes count:        " << local_dpos_total_votes_count;
    LOG(log_nf_) << "PBFT consensus 2t+1 threshold: " << local_twotplusone;
    LOG(log_nf_) << "Node elligible vote count:     " << local_weighted_votes;

    LOG(log_dg_) << "****** Memory structures sizes ******";
    LOG(log_dg_) << "Unverified votes size:           " << vote_mgr_->getUnverifiedVotesSize();
    LOG(log_dg_) << "Verified votes size:             " << vote_mgr_->getVerifiedVotesSize();

    const auto [unverified_txs_size, verified_txs_size] = trx_mgr_->getTransactionQueueSize();
    LOG(log_dg_) << "Unverified txs size:             " << unverified_txs_size;
    LOG(log_dg_) << "Verified txs size:               " << verified_txs_size;
    LOG(log_dg_) << "Txs buffer size:                 " << trx_mgr_->getTransactionBufferSize();

    const auto [unverified_blocks_size, verified_blocks_size] = dag_blk_mgr_->getDagBlockQueueSize();
    const auto [non_finalized_blocks_levels, non_finalized_blocks_size] = dag_mgr_->getNonFinalizedBlocksSize();
    const auto [finalized_blocks_levels, finalized_blocks_size] = dag_mgr_->getFinalizedBlocksSize();
    LOG(log_dg_) << "Unverified dag blocks size:      " << unverified_blocks_size;
    LOG(log_dg_) << "Verified dag blocks size:        " << verified_blocks_size;
    LOG(log_dg_) << "Non finalized dag blocks levels: " << non_finalized_blocks_levels;
    LOG(log_dg_) << "Non finalized dag blocks size:   " << non_finalized_blocks_size;
    LOG(log_dg_) << "Finalized dag blocks levels:     " << finalized_blocks_levels;
    LOG(log_dg_) << "Finalized dag blocks size:       " << finalized_blocks_size;
  }

  LOG(log_nf_) << "------------- tl;dr -------------";

  if (making_pbft_chain_progress) {
    if (is_syncing) {
      LOG(log_nf_) << "STATUS: GOOD. ACTIVELY SYNCING";
    } else if (local_weighted_votes) {
      LOG(log_nf_) << "STATUS: GOOD. NODE SYNCED AND PARTICIPATING IN CONSENSUS";
    } else {
      LOG(log_nf_) << "STATUS: GOOD. NODE SYNCED";
    }
  } else if (is_syncing && (making_pbft_sync_period_progress || making_dag_progress)) {
    LOG(log_nf_) << "STATUS: PENDING SYNCED DATA";
  } else if (!is_syncing && making_pbft_consensus_progress) {
    if (local_weighted_votes) {
      LOG(log_nf_) << "STATUS: PARTICIPATING IN CONSENSUS BUT NO NEW FINALIZED BLOCKS";
    } else {
      LOG(log_nf_) << "STATUS: NODE SYNCED BUT NO NEW FINALIZED BLOCKS";
    }
  } else if (!is_syncing && making_dag_progress) {
    LOG(log_nf_) << "STATUS: PBFT STALLED, POSSIBLY PARTITIONED. NODE HAS NOT RESTARTED SYNCING";
  } else if (peers_size) {
    if (is_syncing) {
      auto syncing_stalled_time_sec = stats_log_interval_ * syncing_stalled_interval_count_ / 1000;
      LOG(log_nf_) << "STATUS: SYNCING STALLED. NO PROGRESS MADE IN LAST " << syncing_stalled_time_sec << " SECONDS";
    } else {
      LOG(log_nf_) << "STATUS: STUCK. NODE HAS NOT RESTARTED SYNCING";
    }
  } else {
    // Peer size is zero...
    LOG(log_nf_) << "STATUS: NOT CONNECTED TO ANY PEERS. POSSIBLE CONFIG ISSUE OR NETWORK CONNECTIVITY";
  }

  LOG(log_nf_) << "In the last " << std::setprecision(0) << stats_log_interval_ / 1000 << " seconds...";

  if (is_syncing) {
    LOG(log_nf_) << "PBFT sync period progress:      " << pbft_sync_period_progress;
  }

  LOG(log_nf_) << "PBFT chain blocks added:        " << pbft_chain_size_growth;
  LOG(log_nf_) << "PBFT rounds advanced:           " << pbft_consensus_rounds_advanced;
  LOG(log_nf_) << "DAG level growth:               " << dag_level_growh;

  LOG(log_nf_) << "##################################";

  // Node stats info history
  local_max_level_in_dag_prev_interval_ = local_max_level_in_dag;
  local_pbft_round_prev_interval_ = local_pbft_round;
  local_chain_size_prev_interval_ = local_chain_size;
  local_pbft_sync_period_prev_interval_ = local_pbft_sync_period;
}

Json::Value NodeStats::getStatus() const {
  Json::Value res;
  NodeID max_pbft_round_nodeID;
  NodeID max_pbft_chain_nodeID;
  NodeID max_node_dag_level_nodeID;
  uint64_t peer_max_pbft_round = 1;
  uint64_t peer_max_pbft_chain_size = 1;
  uint64_t peer_max_node_dag_level = 1;

  res["peers"] = Json::Value(Json::arrayValue);

  for (auto const &peer : peers_state_->getAllPeers()) {
    Json::Value peer_status;
    peer_status["node_id"] = peer.first.toString();
    peer_status["dag_level"] = Json::UInt64(peer.second->dag_level_);
    peer_status["pbft_size"] = Json::UInt64(peer.second->pbft_chain_size_);
    peer_status["dag_synced"] = !peer.second->syncing_;
    res["peers"].append(peer_status);
    // Find max pbft chain size
    if (peer.second->pbft_chain_size_ > peer_max_pbft_chain_size) {
      peer_max_pbft_chain_size = peer.second->pbft_chain_size_;
      max_pbft_chain_nodeID = peer.first;
    }

    // Find max dag level
    if (peer.second->dag_level_ > peer_max_node_dag_level) {
      peer_max_node_dag_level = peer.second->dag_level_;
      max_node_dag_level_nodeID = peer.first;
    }

    // Find max peer PBFT round
    if (peer.second->pbft_round_ > peer_max_pbft_round) {
      peer_max_pbft_round = peer.second->pbft_round_;
      max_pbft_round_nodeID = peer.first;
    }
  }

  if (syncing_state_->is_syncing()) {
    res["syncing_from_node_id"] = syncing_state_->syncing_peer().toString();
  }

  res["peer_max_pbft_round"] = Json::UInt64(peer_max_pbft_round);
  res["peer_max_pbft_chain_size"] = Json::UInt64(peer_max_pbft_chain_size);
  res["peer_max_node_dag_level"] = Json::UInt64(peer_max_node_dag_level);
  res["peer_max_pbft_round_node_id"] = max_pbft_round_nodeID.toString();
  res["peer_max_pbft_chain_size_node_id"] = max_pbft_chain_nodeID.toString();
  res["peer_max_node_dag_level_node_id"] = max_node_dag_level_nodeID.toString();

  // TODO: generate proper node stats
//  auto createPacketsStatsJson = [&](const PacketsStats &stats) -> Json::Value {
//    Json::Value stats_json;
//    for (uint8_t it = 0; it != PacketCount; it++) {
//      Json::Value packet_stats_json;
//      const auto packet_stats = stats.getPacketStats(packetTypeToString(it));
//      if (packet_stats == std::nullopt) {
//        continue;
//      }
//
//      auto total = packet_stats->total_count_;
//      packet_stats_json["total"] = Json::UInt64(total);
//      if (total > 0) {
//        packet_stats_json["avg packet size"] = Json::UInt64(packet_stats->total_size_ / total);
//        packet_stats_json["avg packet processing duration"] =
//            Json::UInt64(packet_stats->total_duration_.count() / total);
//        auto unique = packet_stats->total_unique_count_;
//        if (unique > 0) {
//          packet_stats_json["unique"] = Json::UInt64(unique);
//          packet_stats_json["unique %"] = Json::UInt64(unique * 100 / total);
//          packet_stats_json["unique avg packet size"] = Json::UInt64(packet_stats->total_unique_size_ / unique);
//          packet_stats_json["unique avg packet processing duration"] =
//              Json::UInt64(packet_stats->total_unique_duration_.count() / unique);
//        }
//        stats_json[packetTypeToString(it)] = packet_stats_json;
//      }
//    }
//
//    return stats_json;
//  };
//
//  Json::Value received_packet_stats_json = createPacketsStatsJson(received_packets_stats_);
//
//  received_packet_stats_json["transaction count"] = Json::UInt64(received_trx_count);
//  received_packet_stats_json["unique transaction count"] = Json::UInt64(unique_received_trx_count);
//  if (received_trx_count)
//    received_packet_stats_json["unique transaction %"] =
//        Json::UInt64(unique_received_trx_count * 100 / received_trx_count);
//  res["received packets stats"] = received_packet_stats_json;
//
//  Json::Value sent_packet_stats_json = createPacketsStatsJson(sent_packets_stats_);
//  res["sent packets stats"] = sent_packet_stats_json;

  return res;
}

}  // namespace taraxa::network::tarcap