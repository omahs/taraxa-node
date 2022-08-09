#include "network/tarcap/packets_handlers/common/ext_votes_packet_handler.hpp"

#include "pbft/pbft_manager.hpp"
#include "vote/vote.hpp"

namespace taraxa::network::tarcap {

ExtVotesPacketHandler::ExtVotesPacketHandler(std::shared_ptr<PeersState> peers_state,
                                             std::shared_ptr<PacketsStats> packets_stats,
                                             std::shared_ptr<PbftManager> pbft_mgr, const addr_t &node_addr,
                                             const std::string &log_channel_name)
    : PacketHandler(std::move(peers_state), std::move(packets_stats), node_addr, log_channel_name),
      pbft_mgr_(std::move(pbft_mgr)) {}

void ExtVotesPacketHandler::onNewPbftVotes(std::vector<std::shared_ptr<Vote>> &&votes) {
  for (const auto &peer : peers_state_->getAllPeers()) {
    if (peer.second->syncing_) {
      continue;
    }

    std::vector<std::shared_ptr<Vote>> send_votes;
    for (const auto &v : votes) {
      if (!peer.second->isVoteKnown(v->getHash()) &&
          (peer.second->pbft_round_ <= v->getRound() ||
           (v->getType() == PbftVoteType::cert_vote_type &&
            v->getBlockHash() == pbft_mgr_->getLastPbftBlockHash() /* reward vote */))) {
        send_votes.push_back(v);
      }
    }
    sendPbftVotes(peer.first, std::move(send_votes));
  }
}

void ExtVotesPacketHandler::sendPbftVotes(const dev::p2p::NodeID &peer_id, std::vector<std::shared_ptr<Vote>> &&votes,
                                          bool is_next_votes) {
  if (votes.empty()) {
    return;
  }

  LOG(log_nf_) << "Will send next votes type " << std::boolalpha << is_next_votes;
  auto subprotocol_packet_type =
      is_next_votes ? SubprotocolPacketType::VotesSyncPacket : SubprotocolPacketType::VotePacket;

  size_t index = 0;
  while (index < votes.size()) {
    const size_t count = std::min(static_cast<size_t>(kMaxVotesInPacket), votes.size() - index);
    dev::RLPStream s(count);
    for (auto i = index; i < index + count; i++) {
      const auto &v = votes[i];
      s.appendRaw(v->rlp(true));
      LOG(log_dg_) << "Send out vote " << v->getHash() << " to peer " << peer_id;
    }

    if (sealAndSend(peer_id, subprotocol_packet_type, std::move(s))) {
      LOG(log_nf_) << "Send out size of " << count << " PBFT votes to " << peer_id;
    }

    index += count;
  }

  if (const auto peer = peers_state_->getPeer(peer_id)) {
    for (const auto &v : votes) {
      peer->markVoteAsKnown(v->getHash());
    }
  }
}

}  // namespace taraxa::network::tarcap
