#include "config/state_api_config.hpp"

#include <libdevcore/CommonJS.h>

#include <sstream>

namespace taraxa::state_api {

Json::Value enc_json(const ETHChainConfig& obj) {
  Json::Value json(Json::objectValue);
  json["homestead_block"] = dev::toJS(obj.homestead_block);
  json["dao_fork_block"] = dev::toJS(obj.dao_fork_block);
  json["eip_150_block"] = dev::toJS(obj.eip_150_block);
  json["eip_158_block"] = dev::toJS(obj.eip_158_block);
  json["byzantium_block"] = dev::toJS(obj.byzantium_block);
  json["constantinople_block"] = dev::toJS(obj.constantinople_block);
  json["petersburg_block"] = dev::toJS(obj.petersburg_block);
  return json;
}

void dec_json(const Json::Value& json, ETHChainConfig& obj) {
  obj.homestead_block = dev::jsToInt(json["homestead_block"].asString());
  obj.dao_fork_block = dev::jsToInt(json["dao_fork_block"].asString());
  obj.eip_150_block = dev::jsToInt(json["eip_150_block"].asString());
  obj.eip_158_block = dev::jsToInt(json["eip_158_block"].asString());
  obj.byzantium_block = dev::jsToInt(json["byzantium_block"].asString());
  obj.constantinople_block = dev::jsToInt(json["constantinople_block"].asString());
  obj.petersburg_block = dev::jsToInt(json["petersburg_block"].asString());
}

Json::Value enc_json(const Config& obj) {
  Json::Value json(Json::objectValue);
  json["eth_chain_config"] = enc_json(obj.eth_chain_config);
  json["execution_options"] = enc_json(obj.execution_options);
  json["block_rewards_options"] = enc_json(obj.block_rewards_options);
  json["genesis_balances"] = enc_json(obj.genesis_balances);
  // json["hardforks"] = enc_json(obj.hardforks);
  if (obj.dpos) {
    json["dpos"] = enc_json(*obj.dpos);
  }
  return json;
}

void dec_json(const Json::Value& json, Config& obj) {
  dec_json(json["eth_chain_config"], obj.eth_chain_config);
  dec_json(json["execution_options"], obj.execution_options);
  dec_json(json["block_rewards_options"], obj.block_rewards_options);
  dec_json(json["genesis_balances"], obj.genesis_balances);
  // dec_json(json["hardforks"], obj.hardforks);
  if (const auto& dpos = json["dpos"]; !dpos.isNull()) {
    dec_json(dpos, obj.dpos.emplace());
  }
}

Json::Value enc_json(const BalanceMap& obj) {
  Json::Value json(Json::objectValue);
  for (auto const& [k, v] : obj) {
    json[dev::toJS(k)] = dev::toJS(v);
  }
  return json;
}

void dec_json(const Json::Value& json, BalanceMap& obj) {
  for (const auto& k : json.getMemberNames()) {
    obj[addr_t(k)] = dev::jsToU256(json[k].asString());
  }
}

Json::Value enc_json(const ValidatorInfo& obj) {
  Json::Value json(Json::objectValue);

  json["address"] = dev::toJS(obj.address);
  json["owner"] = dev::toJS(obj.owner);
  json["commission"] = dev::toJS(obj.commission);
  json["endpoint"] = obj.endpoint;
  json["description"] = obj.description;
  json["delegations"] = enc_json(obj.delegations);

  return json;
}
void dec_json(const Json::Value& json, ValidatorInfo& obj) {
  obj.address = addr_t(json["address"].asString());
  obj.owner = addr_t(json["owner"].asString());
  obj.commission = dev::getUInt(json["owner"]);
  obj.endpoint = json["endpoint"].asString();
  obj.description = json["description"].asString();

  dec_json(json["delegations"], obj.delegations);
}

Json::Value enc_json(const DPOSConfig& obj) {
  Json::Value json(Json::objectValue);
  json["eligibility_balance_threshold"] = dev::toJS(obj.eligibility_balance_threshold);
  json["delegation_delay"] = dev::toJS(obj.delegation_delay);
  json["delegation_locking_period"] = dev::toJS(obj.delegation_locking_period);
  json["vote_eligibility_balance_step"] = dev::toJS(obj.vote_eligibility_balance_step);
  json["validator_maximum_stake"] = dev::toJS(obj.validator_maximum_stake);
  json["minimum_deposit"] = dev::toJS(obj.minimum_deposit);
  json["commission_change_delta"] = dev::toJS(obj.commission_change_delta);
  json["commission_change_frequency"] = dev::toJS(obj.commission_change_frequency);
  json["yield_percentage"] = dev::toJS(obj.yield_percentage);
  json["blocks_per_year"] = dev::toJS(obj.blocks_per_year);

  json["initial_validators"] = Json::Value(Json::arrayValue);
  for (const auto& v : obj.initial_validators) {
    json["initial_validators"].append(enc_json(v));
  }
  return json;
}

void dec_json(const Json::Value& json, DPOSConfig& obj) {
  obj.eligibility_balance_threshold = dev::jsToU256(json["eligibility_balance_threshold"].asString());
  obj.delegation_delay = dev::getUInt(json["delegation_delay"].asString());
  obj.delegation_locking_period = dev::getUInt(json["delegation_locking_period"].asString());
  obj.vote_eligibility_balance_step = dev::jsToU256(json["vote_eligibility_balance_step"].asString());
  obj.validator_maximum_stake = dev::jsToU256(json["validator_maximum_stake"].asString());
  obj.minimum_deposit = dev::jsToU256(json["minimum_deposit"].asString());
  obj.commission_change_delta = static_cast<uint16_t>(dev::getUInt(json["commission_change_delta"].asString()));
  obj.commission_change_frequency = dev::getUInt(json["commission_change_frequency"].asString());
  obj.yield_percentage = static_cast<uint16_t>(dev::getUInt(json["yield_percentage"]));
  obj.blocks_per_year = dev::getUInt(json["blocks_per_year"]);

  const auto& initial_validators_json = json["initial_validators"];
  obj.initial_validators.reserve(initial_validators_json.size());
  for (uint32_t i = 0; i < initial_validators_json.size(); ++i) {
    dec_json(initial_validators_json[i], obj.initial_validators[i]);
  }
}

Json::Value enc_json(const ExecutionOptions& obj) {
  Json::Value json(Json::objectValue);
  json["disable_nonce_check"] = obj.disable_nonce_check;
  json["disable_gas_fee"] = obj.disable_gas_fee;
  json["enable_nonce_skipping"] = obj.enable_nonce_skipping;

  return json;
}

void dec_json(const Json::Value& json, ExecutionOptions& obj) {
  obj.disable_nonce_check = json["disable_nonce_check"].asBool();
  obj.disable_gas_fee = json["disable_gas_fee"].asBool();
  obj.enable_nonce_skipping = json["enable_nonce_skipping"].asBool();
}

Json::Value enc_json(BlockRewardsOptions const& obj) {
  Json::Value json(Json::objectValue);
  json["disable_block_rewards"] = obj.disable_block_rewards;
  json["disable_contract_distribution"] = obj.disable_contract_distribution;

  return json;
}

void dec_json(Json::Value const& json, BlockRewardsOptions& obj) {
  obj.disable_block_rewards = json["disable_block_rewards"].asBool();
  obj.disable_contract_distribution = json["disable_contract_distribution"].asBool();
}

RLP_FIELDS_DEFINE(ExecutionOptions, disable_nonce_check, disable_gas_fee, enable_nonce_skipping)
RLP_FIELDS_DEFINE(BlockRewardsOptions, disable_block_rewards, disable_contract_distribution)
RLP_FIELDS_DEFINE(ETHChainConfig, homestead_block, dao_fork_block, eip_150_block, eip_158_block, byzantium_block,
                  constantinople_block, petersburg_block)
RLP_FIELDS_DEFINE(ValidatorInfo, address, owner, commission, endpoint, description, delegations)
RLP_FIELDS_DEFINE(DPOSConfig, eligibility_balance_threshold, vote_eligibility_balance_step, validator_maximum_stake,
                  minimum_deposit, commission_change_delta, commission_change_frequency, delegation_delay,
                  delegation_locking_period, blocks_per_year, yield_percentage, initial_validators)
RLP_FIELDS_DEFINE(Config, eth_chain_config, execution_options, block_rewards_options, genesis_balances, dpos)
RLP_FIELDS_DEFINE(Opts, expected_max_trx_per_block, max_trie_full_node_levels_to_cache)
RLP_FIELDS_DEFINE(OptsDB, db_path, disable_most_recent_trie_value_views)

}  // namespace taraxa::state_api