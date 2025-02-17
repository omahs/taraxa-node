#pragma once

#include "final_chain/data.hpp"

namespace taraxa::net::rpc::eth {

using taraxa::final_chain::LogBloom;
using taraxa::final_chain::LogBlooms;
using taraxa::final_chain::LogEntry;
using taraxa::final_chain::TransactionLocation;
using taraxa::final_chain::TransactionReceipt;

struct TransactionLocationWithBlockHash : TransactionLocation {
  h256 blk_h{};
};

struct LocalisedTransaction {
  std::shared_ptr<Transaction> trx;
  std::optional<TransactionLocationWithBlockHash> trx_loc{};
};

struct ExtendedTransactionLocation : TransactionLocationWithBlockHash {
  h256 trx_hash{};
};

struct LocalisedTransactionReceipt {
  TransactionReceipt r;
  ExtendedTransactionLocation trx_loc;
  addr_t trx_from;
  std::optional<addr_t> trx_to;
};

struct LocalisedLogEntry {
  LogEntry le;
  ExtendedTransactionLocation trx_loc;
  uint64_t position_in_receipt = 0;
};

struct TransactionSkeleton {
  Address from;
  u256 value;
  bytes data;
  std::optional<Address> to;
  std::optional<trx_nonce_t> nonce;
  std::optional<uint64_t> gas;
  std::optional<u256> gas_price;
};

struct SyncStatus {
  EthBlockNumber starting_block = 0, current_block = 0, highest_block = 0;
};

}  // namespace taraxa::net::rpc::eth