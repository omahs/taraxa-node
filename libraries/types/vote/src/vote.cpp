#include "vote/vote.hpp"

#include <boost/math/distributions/binomial.hpp>

namespace taraxa {

VrfPbftSortition::VrfPbftSortition(bytes const& b) {
  dev::RLP const rlp(b);
  if (!rlp.isList()) {
    throw std::invalid_argument("VrfPbftSortition RLP must be a list");
  }
  auto it = rlp.begin();

  pk = (*it++).toHash<vrf_pk_t>();
  pbft_msg.type = PbftVoteTypes((*it++).toInt<uint>());
  pbft_msg.round = (*it++).toInt<uint64_t>();
  pbft_msg.step = (*it++).toInt<size_t>();
  proof = (*it++).toHash<vrf_proof_t>();
}

bytes VrfPbftSortition::getRlpBytes() const {
  dev::RLPStream s;

  s.appendList(5);
  s << pk;
  s << static_cast<uint8_t>(pbft_msg.type);
  s << pbft_msg.round;
  s << pbft_msg.step;
  s << proof;

  return s.out();
}

uint64_t VrfPbftSortition::getBinominalDistribution(uint64_t stake, double dpos_total_votes_count, double threshold,
                                                    const uint512_t& output) {
  auto l = static_cast<uint512_t>(output).convert_to<boost::multiprecision::mpfr_float>();
  auto division = l / kMax512bFP;
  double ratio = division.convert_to<double>();
  boost::math::binomial_distribution<double> dist(static_cast<double>(stake), threshold / dpos_total_votes_count);
  for (uint64_t j = 0; j < stake; ++j) {
    // Found the correct boundary, break
    if (ratio <= cdf(dist, j)) {
      return j;
    }
  }
  return stake;
}

uint64_t VrfPbftSortition::getBinominalDistribution(uint64_t stake, double threshold,
                                                    double dpos_total_votes_count) const {
  return VrfPbftSortition::getBinominalDistribution(stake, threshold, dpos_total_votes_count, output);
}

Vote::Vote(dev::RLP const& rlp) {
  if (!rlp.isList()) throw std::invalid_argument("vote RLP must be a list");
  auto it = rlp.begin();

  blockhash_ = (*it++).toHash<blk_hash_t>();
  vrf_sortition_ = VrfPbftSortition((*it++).toBytes());
  vote_signature_ = (*it++).toHash<sig_t>();
  if (it != rlp.end()) weight_ = (*it).toInt<uint64_t>();
  vote_hash_ = sha3(true);
}

Vote::Vote(bytes const& b) : Vote(dev::RLP(b)) {}

Vote::Vote(secret_t const& node_sk, VrfPbftSortition const& vrf_sortition, blk_hash_t const& blockhash)
    : blockhash_(blockhash), vrf_sortition_(vrf_sortition) {
  vote_signature_ = dev::sign(node_sk, sha3(false));
  vote_hash_ = sha3(true);
}

void Vote::validate(uint64_t stake, double sortition_threshold, double dpos_total_votes_count) const {
  if (!stake || !dpos_total_votes_count) {
    std::stringstream err;
    err << "Invalid stake " << *this;
    throw std::logic_error(err.str());
  }

  if (!verifyVrfSortition()) {
    std::stringstream err;
    err << "Invalid vrf proof. " << *this;
    throw std::logic_error(err.str());
  }

  if (!calculateWeight(stake, sortition_threshold, dpos_total_votes_count)) {
    std::stringstream err;
    err << "Vote sortition failed. Sortition threshold " << sortition_threshold << ", DPOS total votes count "
        << dpos_total_votes_count << " " << *this;
    throw std::logic_error(err.str());
  }

  if (!verifyVote()) {
    std::stringstream err;
    err << "Invalid vote signature. " << dev::toHex(rlp(false)) << "  " << *this;
    throw std::logic_error(err.str());
  }
}

bytes Vote::rlp(bool inc_sig, bool inc_weight) const {
  dev::RLPStream s;
  uint32_t number_of_items = 2;
  if (inc_sig) {
    number_of_items++;
  }
  if (inc_weight && weight_) {
    number_of_items++;
  }

  s.appendList(number_of_items);

  s << blockhash_;
  s << vrf_sortition_.getRlpBytes();
  if (inc_sig) {
    s << vote_signature_;
  }
  if (inc_weight && weight_) {
    s << weight_.value();
  }

  return s.out();
}

}  // namespace taraxa